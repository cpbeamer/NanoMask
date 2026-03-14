const std = @import("std");
const schema_mod = @import("schema.zig");
const Schema = schema_mod.Schema;
const SchemaAction = schema_mod.SchemaAction;

/// Explicit error set for JSON redaction — required because parseObject
/// and parseArray are mutually recursive and Zig cannot infer error sets
/// across recursion boundaries.
pub const RedactError = error{
    InvalidJson,
    OutOfMemory,
    ScanFailed,
    HashFailed,
};

pub const StreamingError = RedactError || std.Io.Writer.Error;

pub const StreamingStats = struct {
    peak_buffered_input_bytes: usize = 0,
    peak_key_stack_bytes: usize = 0,
    peak_pending_key_bytes: usize = 0,
    peak_working_set_bytes: usize = 0,
    bytes_written: usize = 0,
    max_nesting_depth: usize = 0,
};

const NeedMoreInput = error{NeedMoreInput};

/// Context for SCAN-action fields that need the existing 3-stage pipeline.
/// When null, SCAN fields are treated as KEEP (passed through untouched).
///
/// NOTE: This is an internal interface used exclusively by the proxy pipeline
/// and redaction_audit module. The `scan_fn` signature may change between
/// releases without external notice.
pub const ScanContext = struct {
    /// Callback that runs the value through the full redaction pipeline.
    /// Receives the raw field value, the dotted field path (e.g. "address.street"),
    /// an opaque context pointer, and the allocator.
    /// Returns an owned slice with redacted content (caller frees).
    scan_fn: *const fn (input: []const u8, field_path: []const u8, ctx_ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]u8,
    ctx_ptr: *anyopaque,
};

/// Hasher interface for HASH-action fields.
pub const HasherInterface = struct {
    hash_fn: *const fn (original: []const u8, ctx_ptr: *anyopaque) anyerror![]const u8,
    ctx_ptr: *anyopaque,
};

pub const AuditEvent = struct {
    field_path: []const u8,
    action: SchemaAction,
    original_length: usize,
    replacement_type: []const u8,
};

pub const AuditContext = struct {
    audit_fn: *const fn (event: AuditEvent, ctx_ptr: *anyopaque) anyerror!void,
    ctx_ptr: *anyopaque,
};

/// Streaming single-pass JSON redactor.
/// Walks JSON byte-by-byte, tracks current key path via a stack,
/// and applies schema-defined actions to each value.
pub fn redactJson(
    input: []const u8,
    schema: *const Schema,
    hasher: ?HasherInterface,
    scan_ctx: ?ScanContext,
    allocator: std.mem.Allocator,
) RedactError![]u8 {
    return redactJsonWithAudit(input, schema, hasher, scan_ctx, null, allocator);
}

pub fn redactJsonWithAudit(
    input: []const u8,
    schema: *const Schema,
    hasher: ?HasherInterface,
    scan_ctx: ?ScanContext,
    audit_ctx: ?AuditContext,
    allocator: std.mem.Allocator,
) RedactError![]u8 {
    if (input.len == 0) {
        return try allocator.dupe(u8, input);
    }

    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    // Key path stack for tracking nested object context.
    // Each entry is the key name at that nesting level.
    var key_stack = std.ArrayListUnmanaged([]u8).empty;
    defer {
        for (key_stack.items) |k| allocator.free(k);
        key_stack.deinit(allocator);
    }

    var i: usize = 0;
    while (i < input.len) {
        const c = input[i];

        switch (c) {
            '{' => {
                try result.append(allocator, '{');
                i += 1;
                i = try skipWhitespace(input, i);

                // Parse object contents
                i = try parseObject(input, i, schema, hasher, scan_ctx, audit_ctx, &result, &key_stack, allocator);
            },
            '[' => {
                // Top-level array — copy as-is or handle per-element
                try result.append(allocator, '[');
                i += 1;
                i = try parseArray(input, i, schema, hasher, scan_ctx, audit_ctx, &result, &key_stack, allocator);
            },
            else => {
                // Non-JSON or whitespace around root element
                try result.append(allocator, c);
                i += 1;
            },
        }
    }

    return try result.toOwnedSlice(allocator);
}

/// Build the current dotted key path from the stack.
fn buildKeyPath(key_stack: *std.ArrayListUnmanaged([]u8), current_key: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (key_stack.items.len == 0) {
        return try allocator.dupe(u8, current_key);
    }

    var total_len: usize = 0;
    for (key_stack.items) |k| {
        total_len += k.len + 1; // +1 for dot
    }
    total_len += current_key.len;

    var path = try allocator.alloc(u8, total_len);
    var pos: usize = 0;
    for (key_stack.items) |k| {
        @memcpy(path[pos .. pos + k.len], k);
        pos += k.len;
        path[pos] = '.';
        pos += 1;
    }
    @memcpy(path[pos .. pos + current_key.len], current_key);

    return path;
}

fn skipWhitespace(input: []const u8, start: usize) RedactError!usize {
    var i = start;
    while (i < input.len and (input[i] == ' ' or input[i] == '\t' or input[i] == '\n' or input[i] == '\r')) {
        i += 1;
    }
    return i;
}

/// Extract a JSON string starting at `input[start]` (which must be `"`).
/// Returns the content between quotes (unescaped) and the index after the closing quote.
fn extractString(input: []const u8, start: usize) RedactError!struct { content: []const u8, end: usize } {
    if (start >= input.len or input[start] != '"') return error.InvalidJson;

    var i = start + 1;
    const content_start = i;
    while (i < input.len) {
        if (input[i] == '\\') {
            i += 2; // Skip escaped char
            continue;
        }
        if (input[i] == '"') {
            return .{ .content = input[content_start..i], .end = i + 1 };
        }
        i += 1;
    }
    return error.InvalidJson; // Unterminated string
}

/// Extract a JSON value (string, number, boolean, null, object, or array) as raw bytes.
/// Returns the raw slice and the index after the value.
fn extractRawValue(input: []const u8, start: usize) RedactError!struct { raw: []const u8, end: usize } {
    if (start >= input.len) return error.InvalidJson;

    const c = input[start];
    if (c == '"') {
        // String value
        var i = start + 1;
        while (i < input.len) {
            if (input[i] == '\\') {
                i += 2;
                continue;
            }
            if (input[i] == '"') {
                return .{ .raw = input[start .. i + 1], .end = i + 1 };
            }
            i += 1;
        }
        return error.InvalidJson;
    } else if (c == '{') {
        // Object value — find matching close brace
        const end = try findMatchingBrace(input, start);
        return .{ .raw = input[start..end], .end = end };
    } else if (c == '[') {
        // Array value — find matching close bracket
        const end = try findMatchingBracket(input, start);
        return .{ .raw = input[start..end], .end = end };
    } else {
        // Number, boolean, null — scan to next delimiter
        var i = start;
        while (i < input.len) {
            switch (input[i]) {
                ',', '}', ']', ' ', '\t', '\n', '\r' => break,
                else => i += 1,
            }
        }
        if (i == start) return error.InvalidJson;
        return .{ .raw = input[start..i], .end = i };
    }
}

/// Find the index after the matching `}` for an opening `{` at `start`.
fn findMatchingBrace(input: []const u8, start: usize) RedactError!usize {
    var depth: usize = 0;
    var i = start;
    var in_string = false;
    while (i < input.len) {
        if (in_string) {
            if (input[i] == '\\') {
                i += 2;
                continue;
            }
            if (input[i] == '"') in_string = false;
        } else {
            switch (input[i]) {
                '"' => in_string = true,
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if (depth == 0) return i + 1;
                },
                else => {},
            }
        }
        i += 1;
    }
    return error.InvalidJson;
}

/// Find the index after the matching `]` for an opening `[` at `start`.
fn findMatchingBracket(input: []const u8, start: usize) RedactError!usize {
    var depth: usize = 0;
    var i = start;
    var in_string = false;
    while (i < input.len) {
        if (in_string) {
            if (input[i] == '\\') {
                i += 2;
                continue;
            }
            if (input[i] == '"') in_string = false;
        } else {
            switch (input[i]) {
                '"' => in_string = true,
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if (depth == 0) return i + 1;
                },
                else => {},
            }
        }
        i += 1;
    }
    return error.InvalidJson;
}

/// Check if a raw value is a JSON string (starts with `"`).
fn isStringValue(raw: []const u8) bool {
    return raw.len >= 2 and raw[0] == '"';
}

/// Extract the inner content of a JSON string value (without surrounding quotes).
/// Does NOT unescape — returns the raw inner bytes between the quotes.
///
/// KNOWN LIMITATION: JSON escape sequences (e.g. `\"`, `\n`, `\\`) remain in
/// their escaped form. SCAN callbacks will receive `line1\nline2` as literal
/// backslash-n rather than a newline character. This is acceptable for MVP
/// pattern detection but should be revisited if byte-exact matching matters.
fn innerStringContent(raw: []const u8) []const u8 {
    if (raw.len >= 2 and raw[0] == '"' and raw[raw.len - 1] == '"') {
        return raw[1 .. raw.len - 1];
    }
    return raw;
}

fn auditValueLength(raw: []const u8) usize {
    return if (isStringValue(raw)) innerStringContent(raw).len else raw.len;
}

/// Parse the interior of a JSON object (after the opening `{`).
/// Processes key-value pairs and applies schema actions.
/// Returns index after the closing `}`.
fn parseObject(
    input: []const u8,
    start: usize,
    schema: *const Schema,
    hasher: ?HasherInterface,
    scan_ctx: ?ScanContext,
    audit_ctx: ?AuditContext,
    result: *std.ArrayListUnmanaged(u8),
    key_stack: *std.ArrayListUnmanaged([]u8),
    allocator: std.mem.Allocator,
) RedactError!usize {
    var i = start;
    var first_pair = true;

    while (i < input.len) {
        i = try skipWhitespace(input, i);
        if (i >= input.len) return error.InvalidJson;

        // End of object
        if (input[i] == '}') {
            try result.append(allocator, '}');
            return i + 1;
        }

        // Comma between pairs
        if (!first_pair) {
            if (input[i] != ',') return error.InvalidJson;
            try result.append(allocator, ',');
            i += 1;
            i = try skipWhitespace(input, i);
        }
        first_pair = false;

        // Parse key
        const key_info = try extractString(input, i);
        const key_name = key_info.content;
        i = key_info.end;

        i = try skipWhitespace(input, i);
        if (i >= input.len or input[i] != ':') return error.InvalidJson;
        i += 1; // skip ':'
        i = try skipWhitespace(input, i);

        // Build the full dotted key path for schema lookup
        const full_path = try buildKeyPath(key_stack, key_name, allocator);
        defer allocator.free(full_path);

        const action = schema.findAction(full_path);

        // Check if value is a nested object that needs recursive processing
        if (i < input.len and input[i] == '{') {
            // For nested objects, push key onto stack and recurse
            // regardless of the action — we need field-level granularity
            try result.append(allocator, '"');
            try result.appendSlice(allocator, key_name);
            try result.appendSlice(allocator, "\":");

            try result.append(allocator, '{');
            i += 1;

            const owned_key = try allocator.dupe(u8, key_name);
            try key_stack.append(allocator, owned_key);

            i = try parseObject(input, i, schema, hasher, scan_ctx, audit_ctx, result, key_stack, allocator);

            // Free the owned key before removing from stack.
            // Using getLast + manual shrink to avoid pop() return type
            // incompatibility with allocator.free in Zig 0.15.
            const last_idx = key_stack.items.len - 1;
            const owned = key_stack.items[last_idx];
            key_stack.items.len = last_idx;
            allocator.free(owned);
            continue;
        }

        // Check if value is an array
        if (i < input.len and input[i] == '[') {
            try result.append(allocator, '"');
            try result.appendSlice(allocator, key_name);
            try result.appendSlice(allocator, "\":");

            try result.append(allocator, '[');
            i += 1;

            i = try parseArray(input, i, schema, hasher, scan_ctx, audit_ctx, result, key_stack, allocator);
            continue;
        }

        // Extract the value
        const val_info = try extractRawValue(input, i);
        i = val_info.end;

        // Write key
        try result.append(allocator, '"');
        try result.appendSlice(allocator, key_name);
        try result.appendSlice(allocator, "\":");

        // Apply action
        switch (action) {
            .keep => {
                try result.appendSlice(allocator, val_info.raw);
            },
            .redact => {
                if (audit_ctx) |audit| {
                    audit.audit_fn(.{
                        .field_path = full_path,
                        .action = .redact,
                        .original_length = auditValueLength(val_info.raw),
                        .replacement_type = if (isStringValue(val_info.raw)) "redacted" else "null",
                    }, audit.ctx_ptr) catch return error.ScanFailed;
                }
                if (isStringValue(val_info.raw)) {
                    try result.appendSlice(allocator, "\"[REDACTED]\"");
                } else {
                    try result.appendSlice(allocator, "null");
                }
            },
            .scan => {
                if (audit_ctx) |audit| {
                    audit.audit_fn(.{
                        .field_path = full_path,
                        .action = .scan,
                        .original_length = auditValueLength(val_info.raw),
                        .replacement_type = if (isStringValue(val_info.raw)) "scan_pipeline" else "pass_through",
                    }, audit.ctx_ptr) catch return error.ScanFailed;
                }
                if (isStringValue(val_info.raw) and scan_ctx != null) {
                    const inner = innerStringContent(val_info.raw);
                    const scanned = scan_ctx.?.scan_fn(inner, full_path, scan_ctx.?.ctx_ptr, allocator) catch return error.ScanFailed;
                    defer allocator.free(scanned);
                    try result.append(allocator, '"');
                    try result.appendSlice(allocator, scanned);
                    try result.append(allocator, '"');
                } else {
                    // No scan context or not a string — pass through
                    try result.appendSlice(allocator, val_info.raw);
                }
            },
            .hash => {
                if (audit_ctx) |audit| {
                    audit.audit_fn(.{
                        .field_path = full_path,
                        .action = .hash,
                        .original_length = auditValueLength(val_info.raw),
                        .replacement_type = if (isStringValue(val_info.raw) and hasher != null) "pseudonymized" else if (isStringValue(val_info.raw)) "redacted" else "null",
                    }, audit.ctx_ptr) catch return error.HashFailed;
                }
                if (isStringValue(val_info.raw) and hasher != null) {
                    const inner = innerStringContent(val_info.raw);
                    const hashed = hasher.?.hash_fn(inner, hasher.?.ctx_ptr) catch return error.HashFailed;
                    defer allocator.free(@constCast(hashed));
                    try result.append(allocator, '"');
                    try result.appendSlice(allocator, hashed);
                    try result.append(allocator, '"');
                } else if (isStringValue(val_info.raw)) {
                    // No hasher — fall back to REDACT
                    try result.appendSlice(allocator, "\"[REDACTED]\"");
                } else {
                    try result.appendSlice(allocator, "null");
                }
            },
        }
    }

    return error.InvalidJson; // No closing brace found
}

/// Parse the interior of a JSON array (after the opening `[`).
/// Returns index after the closing `]`.
fn parseArray(
    input: []const u8,
    start: usize,
    schema: *const Schema,
    hasher: ?HasherInterface,
    scan_ctx: ?ScanContext,
    audit_ctx: ?AuditContext,
    result: *std.ArrayListUnmanaged(u8),
    key_stack: *std.ArrayListUnmanaged([]u8),
    allocator: std.mem.Allocator,
) RedactError!usize {
    var i = start;
    var first_elem = true;

    while (i < input.len) {
        i = try skipWhitespace(input, i);
        if (i >= input.len) return error.InvalidJson;

        if (input[i] == ']') {
            try result.append(allocator, ']');
            return i + 1;
        }

        if (!first_elem) {
            if (input[i] != ',') return error.InvalidJson;
            try result.append(allocator, ',');
            i += 1;
            i = try skipWhitespace(input, i);
        }
        first_elem = false;

        // Array elements — if object, recurse with current key stack context
        if (i < input.len and input[i] == '{') {
            try result.append(allocator, '{');
            i += 1;
            i = try parseObject(input, i, schema, hasher, scan_ctx, audit_ctx, result, key_stack, allocator);
        } else if (i < input.len and input[i] == '[') {
            try result.append(allocator, '[');
            i += 1;
            i = try parseArray(input, i, schema, hasher, scan_ctx, audit_ctx, result, key_stack, allocator);
        } else {
            // Primitive value in array — pass through
            const val_info = try extractRawValue(input, i);
            try result.appendSlice(allocator, val_info.raw);
            i = val_info.end;
        }
    }

    return error.InvalidJson;
}

const ObjectState = enum {
    expect_key_or_end,
    expect_colon,
    expect_value,
    expect_comma_or_end,
};

const ArrayState = enum {
    expect_value_or_end,
    expect_comma_or_end,
};

const Frame = union(enum) {
    object: struct {
        state: ObjectState = .expect_key_or_end,
        pending_key: ?[]u8 = null,
        stack_key_owned: ?[]u8 = null,
    },
    array: struct {
        state: ArrayState = .expect_value_or_end,
    },
};

/// Incremental schema-aware JSON redactor used by the proxy request path.
/// It only retains unread parser input, nesting metadata, and the current key,
/// instead of buffering the full JSON document before applying schema actions.
pub const ChunkedRedactor = struct {
    schema: *const Schema,
    hasher: ?HasherInterface,
    scan_ctx: ?ScanContext,
    audit_ctx: ?AuditContext,
    writer: *std.Io.Writer,
    allocator: std.mem.Allocator,
    input_buf: std.ArrayListUnmanaged(u8) = .empty,
    input_cursor: usize = 0,
    frames: std.ArrayListUnmanaged(Frame) = .empty,
    key_stack: std.ArrayListUnmanaged([]u8) = .empty,
    root_started: bool = false,
    root_complete: bool = false,
    finished_input: bool = false,
    stats: StreamingStats = .{},

    pub fn init(
        schema: *const Schema,
        hasher: ?HasherInterface,
        scan_ctx: ?ScanContext,
        audit_ctx: ?AuditContext,
        writer: *std.Io.Writer,
        allocator: std.mem.Allocator,
    ) ChunkedRedactor {
        var self = ChunkedRedactor{
            .schema = schema,
            .hasher = hasher,
            .scan_ctx = scan_ctx,
            .audit_ctx = audit_ctx,
            .writer = writer,
            .allocator = allocator,
        };
        self.noteState();
        return self;
    }

    pub fn deinit(self: *ChunkedRedactor) void {
        for (self.frames.items) |frame| {
            switch (frame) {
                .object => |obj| if (obj.pending_key) |key| self.allocator.free(key),
                .array => {},
            }
        }
        self.frames.deinit(self.allocator);

        for (self.key_stack.items) |key| self.allocator.free(key);
        self.key_stack.deinit(self.allocator);

        self.input_buf.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn writeChunk(self: *ChunkedRedactor, chunk: []const u8) StreamingError!void {
        if (self.finished_input) return error.InvalidJson;
        if (chunk.len == 0) return;

        try self.input_buf.appendSlice(self.allocator, chunk);
        self.noteState();
        try self.processAvailable(false);
        self.compactInputBuffer();
        self.noteState();
    }

    pub fn finish(self: *ChunkedRedactor) StreamingError!StreamingStats {
        self.finished_input = true;
        try self.processAvailable(true);
        if (!self.root_started) {
            self.skipWhitespace();
            if (self.input_cursor != self.input_buf.items.len) return error.InvalidJson;
            self.compactInputBuffer();
            self.noteState();
            return self.stats;
        }
        self.skipWhitespace();
        if (!self.root_started or !self.root_complete or self.frames.items.len != 0) {
            return error.InvalidJson;
        }
        if (self.input_cursor != self.input_buf.items.len) {
            return error.InvalidJson;
        }
        self.compactInputBuffer();
        self.noteState();
        return self.stats;
    }

    fn processAvailable(self: *ChunkedRedactor, allow_eof: bool) StreamingError!void {
        while (true) {
            const progressed = self.step(allow_eof) catch |err| switch (err) {
                error.NeedMoreInput => break,
                else => |other| return other,
            };
            if (!progressed) break;
            self.compactInputBuffer();
        }
    }

    fn step(self: *ChunkedRedactor, allow_eof: bool) (StreamingError || NeedMoreInput)!bool {
        self.skipWhitespace();

        if (self.root_complete) {
            return self.input_cursor < self.input_buf.items.len;
        }

        if (!self.root_started) {
            if (self.input_cursor >= self.input_buf.items.len) {
                if (allow_eof) return false;
                return error.NeedMoreInput;
            }
            self.root_started = true;
            try self.parseFreeValue(allow_eof);
            return true;
        }

        if (self.frames.items.len == 0) {
            self.root_complete = true;
            return false;
        }

        const frame_idx = self.frames.items.len - 1;
        switch (self.frames.items[frame_idx]) {
            .object => |*obj| switch (obj.state) {
                .expect_key_or_end => {
                    if (self.input_cursor >= self.input_buf.items.len) {
                        if (allow_eof) return error.InvalidJson;
                        return error.NeedMoreInput;
                    }

                    if (self.input_buf.items[self.input_cursor] == '}') {
                        self.input_cursor += 1;
                        try self.writeByte('}');
                        self.popFrame(frame_idx);
                        return true;
                    }

                    const key = try self.readRawString(allow_eof);
                    self.input_cursor = key.end;
                    try self.writeBytes(key.raw);
                    obj.pending_key = try self.allocator.dupe(u8, key.inner);
                    obj.state = .expect_colon;
                    self.noteState();
                    return true;
                },
                .expect_colon => {
                    self.skipWhitespace();
                    if (self.input_cursor >= self.input_buf.items.len) {
                        if (allow_eof) return error.InvalidJson;
                        return error.NeedMoreInput;
                    }
                    if (self.input_buf.items[self.input_cursor] != ':') return error.InvalidJson;
                    self.input_cursor += 1;
                    try self.writeByte(':');
                    obj.state = .expect_value;
                    return true;
                },
                .expect_value => {
                    self.skipWhitespace();
                    if (self.input_cursor >= self.input_buf.items.len) {
                        if (allow_eof) return error.InvalidJson;
                        return error.NeedMoreInput;
                    }

                    const key_owned = obj.pending_key orelse return error.InvalidJson;
                    const next = self.input_buf.items[self.input_cursor];
                    if (next == '{') {
                        obj.pending_key = null;
                        obj.state = .expect_comma_or_end;
                        errdefer self.allocator.free(key_owned);
                        self.input_cursor += 1;
                        try self.writeByte('{');
                        try self.pushObjectFrame(key_owned);
                        return true;
                    }
                    if (next == '[') {
                        obj.pending_key = null;
                        obj.state = .expect_comma_or_end;
                        defer self.allocator.free(key_owned);
                        self.input_cursor += 1;
                        try self.writeByte('[');
                        try self.pushArrayFrame();
                        return true;
                    }

                    const value = try self.readRawValue(allow_eof);
                    obj.pending_key = null;
                    obj.state = .expect_comma_or_end;
                    defer self.allocator.free(key_owned);
                    self.input_cursor = value.end;
                    try self.applyPrimitiveAction(key_owned, value.raw);
                    return true;
                },
                .expect_comma_or_end => {
                    self.skipWhitespace();
                    if (self.input_cursor >= self.input_buf.items.len) {
                        if (allow_eof) return error.InvalidJson;
                        return error.NeedMoreInput;
                    }

                    switch (self.input_buf.items[self.input_cursor]) {
                        ',' => {
                            self.input_cursor += 1;
                            try self.writeByte(',');
                            obj.state = .expect_key_or_end;
                            return true;
                        },
                        '}' => {
                            self.input_cursor += 1;
                            try self.writeByte('}');
                            self.popFrame(frame_idx);
                            return true;
                        },
                        else => return error.InvalidJson,
                    }
                },
            },
            .array => |*arr| switch (arr.state) {
                .expect_value_or_end => {
                    if (self.input_cursor >= self.input_buf.items.len) {
                        if (allow_eof) return error.InvalidJson;
                        return error.NeedMoreInput;
                    }
                    if (self.input_buf.items[self.input_cursor] == ']') {
                        self.input_cursor += 1;
                        try self.writeByte(']');
                        self.popFrame(frame_idx);
                        return true;
                    }
                    arr.state = .expect_comma_or_end;
                    try self.parseFreeValue(allow_eof);
                    return true;
                },
                .expect_comma_or_end => {
                    self.skipWhitespace();
                    if (self.input_cursor >= self.input_buf.items.len) {
                        if (allow_eof) return error.InvalidJson;
                        return error.NeedMoreInput;
                    }

                    switch (self.input_buf.items[self.input_cursor]) {
                        ',' => {
                            self.input_cursor += 1;
                            try self.writeByte(',');
                            arr.state = .expect_value_or_end;
                            return true;
                        },
                        ']' => {
                            self.input_cursor += 1;
                            try self.writeByte(']');
                            self.popFrame(frame_idx);
                            return true;
                        },
                        else => return error.InvalidJson,
                    }
                },
            },
        }
    }

    fn parseFreeValue(self: *ChunkedRedactor, allow_eof: bool) (StreamingError || NeedMoreInput)!void {
        if (self.input_cursor >= self.input_buf.items.len) {
            if (allow_eof) return error.InvalidJson;
            return error.NeedMoreInput;
        }

        switch (self.input_buf.items[self.input_cursor]) {
            '{' => {
                self.input_cursor += 1;
                try self.writeByte('{');
                try self.pushObjectFrame(null);
            },
            '[' => {
                self.input_cursor += 1;
                try self.writeByte('[');
                try self.pushArrayFrame();
            },
            else => {
                const value = try self.readRawValue(allow_eof);
                self.input_cursor = value.end;
                try self.writeBytes(value.raw);
                if (self.frames.items.len == 0) self.root_complete = true;
            },
        }
    }

    fn pushObjectFrame(self: *ChunkedRedactor, stack_key_owned: ?[]u8) !void {
        if (stack_key_owned) |key| {
            try self.key_stack.append(self.allocator, key);
        }
        try self.frames.append(self.allocator, .{
            .object = .{
                .stack_key_owned = stack_key_owned,
            },
        });
        self.noteState();
    }

    fn pushArrayFrame(self: *ChunkedRedactor) !void {
        try self.frames.append(self.allocator, .{
            .array = .{},
        });
        self.noteState();
    }

    fn popFrame(self: *ChunkedRedactor, frame_idx: usize) void {
        const frame = self.frames.items[frame_idx];
        self.frames.items.len = frame_idx;

        switch (frame) {
            .object => |obj| {
                if (obj.pending_key) |key| self.allocator.free(key);
                if (obj.stack_key_owned) |owned| {
                    const last_idx = self.key_stack.items.len - 1;
                    self.key_stack.items.len = last_idx;
                    self.allocator.free(owned);
                }
            },
            .array => {},
        }

        if (self.frames.items.len == 0) self.root_complete = true;
        self.noteState();
    }

    fn applyPrimitiveAction(self: *ChunkedRedactor, key_owned: []const u8, raw_value: []const u8) StreamingError!void {
        const full_path = try buildKeyPath(&self.key_stack, key_owned, self.allocator);
        defer self.allocator.free(full_path);

        const action = self.schema.findAction(full_path);
        switch (action) {
            .keep => {
                try self.writeBytes(raw_value);
            },
            .redact => {
                if (self.audit_ctx) |audit| {
                    audit.audit_fn(.{
                        .field_path = full_path,
                        .action = .redact,
                        .original_length = auditValueLength(raw_value),
                        .replacement_type = if (isStringValue(raw_value)) "redacted" else "null",
                    }, audit.ctx_ptr) catch return error.ScanFailed;
                }
                if (isStringValue(raw_value)) {
                    try self.writeBytes("\"[REDACTED]\"");
                } else {
                    try self.writeBytes("null");
                }
            },
            .scan => {
                if (self.audit_ctx) |audit| {
                    audit.audit_fn(.{
                        .field_path = full_path,
                        .action = .scan,
                        .original_length = auditValueLength(raw_value),
                        .replacement_type = if (isStringValue(raw_value)) "scan_pipeline" else "pass_through",
                    }, audit.ctx_ptr) catch return error.ScanFailed;
                }
                if (isStringValue(raw_value) and self.scan_ctx != null) {
                    const inner = innerStringContent(raw_value);
                    const scanned = self.scan_ctx.?.scan_fn(inner, full_path, self.scan_ctx.?.ctx_ptr, self.allocator) catch return error.ScanFailed;
                    defer self.allocator.free(scanned);
                    try self.writeByte('"');
                    try self.writeBytes(scanned);
                    try self.writeByte('"');
                } else {
                    try self.writeBytes(raw_value);
                }
            },
            .hash => {
                if (self.audit_ctx) |audit| {
                    audit.audit_fn(.{
                        .field_path = full_path,
                        .action = .hash,
                        .original_length = auditValueLength(raw_value),
                        .replacement_type = if (isStringValue(raw_value) and self.hasher != null) "pseudonymized" else if (isStringValue(raw_value)) "redacted" else "null",
                    }, audit.ctx_ptr) catch return error.HashFailed;
                }
                if (isStringValue(raw_value) and self.hasher != null) {
                    const inner = innerStringContent(raw_value);
                    const hashed = self.hasher.?.hash_fn(inner, self.hasher.?.ctx_ptr) catch return error.HashFailed;
                    defer self.allocator.free(@constCast(hashed));
                    try self.writeByte('"');
                    try self.writeBytes(hashed);
                    try self.writeByte('"');
                } else if (isStringValue(raw_value)) {
                    try self.writeBytes("\"[REDACTED]\"");
                } else {
                    try self.writeBytes("null");
                }
            },
        }
    }

    fn readRawValue(self: *ChunkedRedactor, allow_eof: bool) (RedactError || NeedMoreInput)!struct { raw: []const u8, end: usize } {
        if (self.input_cursor >= self.input_buf.items.len) {
            if (allow_eof) return error.InvalidJson;
            return error.NeedMoreInput;
        }

        return switch (self.input_buf.items[self.input_cursor]) {
            '"' => blk: {
                const string_value = try self.readRawString(allow_eof);
                break :blk .{
                    .raw = string_value.raw,
                    .end = string_value.end,
                };
            },
            else => blk: {
                const primitive = try self.readRawPrimitive(allow_eof);
                break :blk .{
                    .raw = primitive.raw,
                    .end = primitive.end,
                };
            },
        };
    }

    fn readRawString(self: *ChunkedRedactor, allow_eof: bool) (RedactError || NeedMoreInput)!struct { raw: []const u8, inner: []const u8, end: usize } {
        if (self.input_cursor >= self.input_buf.items.len or self.input_buf.items[self.input_cursor] != '"') {
            return error.InvalidJson;
        }

        var i = self.input_cursor + 1;
        while (i < self.input_buf.items.len) : (i += 1) {
            if (self.input_buf.items[i] == '\\') {
                i += 1;
                if (i >= self.input_buf.items.len) {
                    if (allow_eof) return error.InvalidJson;
                    return error.NeedMoreInput;
                }
                continue;
            }
            if (self.input_buf.items[i] == '"') {
                return .{
                    .raw = self.input_buf.items[self.input_cursor .. i + 1],
                    .inner = self.input_buf.items[self.input_cursor + 1 .. i],
                    .end = i + 1,
                };
            }
        }

        if (allow_eof) return error.InvalidJson;
        return error.NeedMoreInput;
    }

    fn readRawPrimitive(self: *ChunkedRedactor, allow_eof: bool) (RedactError || NeedMoreInput)!struct { raw: []const u8, end: usize } {
        var i = self.input_cursor;
        while (i < self.input_buf.items.len) : (i += 1) {
            switch (self.input_buf.items[i]) {
                ',', '}', ']', ' ', '\t', '\n', '\r' => break,
                else => {},
            }
        }

        if (i == self.input_cursor) return error.InvalidJson;
        if (i == self.input_buf.items.len and !allow_eof) return error.NeedMoreInput;

        return .{
            .raw = self.input_buf.items[self.input_cursor..i],
            .end = i,
        };
    }

    fn skipWhitespace(self: *ChunkedRedactor) void {
        while (self.input_cursor < self.input_buf.items.len) {
            switch (self.input_buf.items[self.input_cursor]) {
                ' ', '\t', '\n', '\r' => self.input_cursor += 1,
                else => return,
            }
        }
    }

    fn compactInputBuffer(self: *ChunkedRedactor) void {
        if (self.input_cursor == 0) return;
        if (self.input_cursor >= self.input_buf.items.len) {
            self.input_buf.items.len = 0;
            self.input_cursor = 0;
            return;
        }
        const remaining = self.input_buf.items.len - self.input_cursor;
        std.mem.copyForwards(u8, self.input_buf.items[0..remaining], self.input_buf.items[self.input_cursor..]);
        self.input_buf.items.len = remaining;
        self.input_cursor = 0;
    }

    fn writeByte(self: *ChunkedRedactor, byte: u8) StreamingError!void {
        try self.writer.writeByte(byte);
        self.stats.bytes_written += 1;
    }

    fn writeBytes(self: *ChunkedRedactor, bytes: []const u8) StreamingError!void {
        if (bytes.len == 0) return;
        try self.writer.writeAll(bytes);
        self.stats.bytes_written += bytes.len;
    }

    fn noteState(self: *ChunkedRedactor) void {
        const buffered_input = self.input_buf.items.len - self.input_cursor;
        const key_stack_bytes = totalKeyBytes(&self.key_stack);
        const pending_key_bytes = self.pendingKeyBytes();
        const working_set_bytes =
            self.input_buf.capacity +
            self.frames.capacity * @sizeOf(Frame) +
            self.key_stack.capacity * @sizeOf([]u8) +
            key_stack_bytes +
            pending_key_bytes;

        if (buffered_input > self.stats.peak_buffered_input_bytes) {
            self.stats.peak_buffered_input_bytes = buffered_input;
        }
        if (key_stack_bytes > self.stats.peak_key_stack_bytes) {
            self.stats.peak_key_stack_bytes = key_stack_bytes;
        }
        if (pending_key_bytes > self.stats.peak_pending_key_bytes) {
            self.stats.peak_pending_key_bytes = pending_key_bytes;
        }
        if (working_set_bytes > self.stats.peak_working_set_bytes) {
            self.stats.peak_working_set_bytes = working_set_bytes;
        }
        if (self.frames.items.len > self.stats.max_nesting_depth) {
            self.stats.max_nesting_depth = self.frames.items.len;
        }
    }

    fn pendingKeyBytes(self: *const ChunkedRedactor) usize {
        var total: usize = 0;
        for (self.frames.items) |frame| {
            switch (frame) {
                .object => |obj| {
                    if (obj.pending_key) |key| total += key.len;
                },
                .array => {},
            }
        }
        return total;
    }
};

fn totalKeyBytes(key_stack: *const std.ArrayListUnmanaged([]u8)) usize {
    var total: usize = 0;
    for (key_stack.items) |key| total += key.len;
    return total;
}

pub fn redactJsonStreaming(
    input: []const u8,
    chunk_size: usize,
    schema: *const Schema,
    hasher: ?HasherInterface,
    scan_ctx: ?ScanContext,
    audit_ctx: ?AuditContext,
    allocator: std.mem.Allocator,
) StreamingError!struct { output: []u8, stats: StreamingStats } {
    var sink: std.Io.Writer.Allocating = .init(allocator);
    defer sink.deinit();

    var redactor = ChunkedRedactor.init(schema, hasher, scan_ctx, audit_ctx, &sink.writer, allocator);
    defer redactor.deinit();

    const effective_chunk_size = if (chunk_size == 0) input.len else chunk_size;
    var offset: usize = 0;
    while (offset < input.len) {
        const end = @min(offset + effective_chunk_size, input.len);
        try redactor.writeChunk(input[offset..end]);
        offset = end;
    }
    const stats = try redactor.finish();
    return .{
        .output = try sink.toOwnedSlice(),
        .stats = stats,
    };
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "json_redactor - streaming matches buffered output across chunk sizes" {
    const ScanMaskCtx = struct {
        fn doScan(input_val: []const u8, _: []const u8, _: *anyopaque, alloc: std.mem.Allocator) ![]u8 {
            if (std.mem.indexOf(u8, input_val, "123-45-6789")) |pos| {
                const replacement = "***-**-****";
                var out = try alloc.alloc(u8, input_val.len - 11 + replacement.len);
                @memcpy(out[0..pos], input_val[0..pos]);
                @memcpy(out[pos .. pos + replacement.len], replacement);
                @memcpy(out[pos + replacement.len ..], input_val[pos + 11 ..]);
                return out;
            }
            return try alloc.dupe(u8, input_val);
        }
    };

    const schema_content =
        \\schema.default = KEEP
        \\patient_name = REDACT
        \\internal_id = HASH
        \\notes = SCAN
        \\details.zip = REDACT
        \\details.state = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const mem_vault1 = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault1.vaultInterface().deinit();
    var buffered_hasher = try @import("hasher.zig").Hasher.init(key_hex, mem_vault1.vaultInterface(), std.testing.allocator);
    defer buffered_hasher.deinit();
    
    const mem_vault2 = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault2.vaultInterface().deinit();
    var streaming_hasher = try @import("hasher.zig").Hasher.init(key_hex, mem_vault2.vaultInterface(), std.testing.allocator);
    defer streaming_hasher.deinit();

    var dummy: u8 = 0;
    const scan_ctx = ScanContext{
        .scan_fn = &ScanMaskCtx.doScan,
        .ctx_ptr = @ptrCast(&dummy),
    };

    const buffered_hash = HasherInterface{
        .hash_fn = &struct {
            fn call(original: []const u8, ctx_ptr: *anyopaque) ![]const u8 {
                const hasher: *@import("hasher.zig").Hasher = @ptrCast(@alignCast(ctx_ptr));
                return hasher.hash(original);
            }
        }.call,
        .ctx_ptr = @ptrCast(&buffered_hasher),
    };
    const streaming_hash = HasherInterface{
        .hash_fn = &struct {
            fn call(original: []const u8, ctx_ptr: *anyopaque) ![]const u8 {
                const hasher: *@import("hasher.zig").Hasher = @ptrCast(@alignCast(ctx_ptr));
                return hasher.hash(original);
            }
        }.call,
        .ctx_ptr = @ptrCast(&streaming_hasher),
    };

    const input =
        \\{"records":[{"patient_name":"Jane Smith","internal_id":"PT-99001","notes":"SSN 123-45-6789 appears here","details":{"zip":"62704","state":"IL"}},{"patient_name":"John Doe","internal_id":"PT-99002","notes":"clean","details":{"zip":"01010","state":"MA"}}]}
    ;

    const buffered = try redactJson(input, &schema, buffered_hash, scan_ctx, std.testing.allocator);
    defer std.testing.allocator.free(buffered);

    for ([_]usize{ 1, 2, 5, 17, 64 }) |chunk_size| {
        const streamed = try redactJsonStreaming(input, chunk_size, &schema, streaming_hash, scan_ctx, null, std.testing.allocator);
        defer std.testing.allocator.free(streamed.output);

        try std.testing.expectEqualStrings(buffered, streamed.output);
        try std.testing.expect(streamed.stats.peak_buffered_input_bytes < input.len);
    }
}

test "json_redactor - streaming keeps bounded working set on large payload" {
    var payload = std.ArrayListUnmanaged(u8).empty;
    defer payload.deinit(std.testing.allocator);

    try payload.appendSlice(std.testing.allocator, "{\"records\":[");
    for (0..1024) |idx| {
        if (idx != 0) try payload.append(std.testing.allocator, ',');
        try payload.writer(std.testing.allocator).print(
            "{{\"patient_name\":\"Patient {d}\",\"internal_id\":\"PT-{d:0>5}\",\"notes\":\"Patient SSN 123-45-6789 requires follow up.\",\"details\":{{\"zip\":\"62704\",\"state\":\"IL\"}}}}",
            .{ idx, idx },
        );
    }
    try payload.appendSlice(std.testing.allocator, "]}");

    const schema_content =
        \\schema.default = KEEP
        \\patient_name = REDACT
        \\internal_id = HASH
        \\notes = SCAN
        \\details.zip = REDACT
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var hasher = try @import("hasher.zig").Hasher.init(key_hex, mem_vault.vaultInterface(), std.testing.allocator);
    defer hasher.deinit();

    var dummy: u8 = 0;
    const scan_ctx = ScanContext{
        .scan_fn = &struct {
            fn doScan(input_val: []const u8, _: []const u8, _: *anyopaque, alloc: std.mem.Allocator) ![]u8 {
                if (std.mem.indexOf(u8, input_val, "123-45-6789")) |pos| {
                    const replacement = "***-**-****";
                    var out = try alloc.alloc(u8, input_val.len - 11 + replacement.len);
                    @memcpy(out[0..pos], input_val[0..pos]);
                    @memcpy(out[pos .. pos + replacement.len], replacement);
                    @memcpy(out[pos + replacement.len ..], input_val[pos + 11 ..]);
                    return out;
                }
                return try alloc.dupe(u8, input_val);
            }
        }.doScan,
        .ctx_ptr = @ptrCast(&dummy),
    };

    const hasher_iface = HasherInterface{
        .hash_fn = &struct {
            fn call(original: []const u8, ctx_ptr: *anyopaque) ![]const u8 {
                const active_hasher: *@import("hasher.zig").Hasher = @ptrCast(@alignCast(ctx_ptr));
                return active_hasher.hash(original);
            }
        }.call,
        .ctx_ptr = @ptrCast(&hasher),
    };

    const reference = try redactJson(payload.items, &schema, hasher_iface, scan_ctx, std.testing.allocator);
    defer std.testing.allocator.free(reference);

    const streamed = try redactJsonStreaming(payload.items, 4096, &schema, hasher_iface, scan_ctx, null, std.testing.allocator);
    defer std.testing.allocator.free(streamed.output);

    try std.testing.expectEqualStrings(reference, streamed.output);
    try std.testing.expect(payload.items.len > 128 * 1024);
    try std.testing.expect(streamed.stats.peak_working_set_bytes < 64 * 1024);
    try std.testing.expect(streamed.stats.peak_buffered_input_bytes < 16 * 1024);
}

test "json_redactor - flat REDACT and KEEP" {
    const schema_content =
        \\patient_name = REDACT
        \\visit_date = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"patient_name":"John Doe","visit_date":"2024-01-15"}
    ;

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"patient_name":"[REDACTED]","visit_date":"2024-01-15"}
    , output);
}

test "json_redactor - nested object" {
    const schema_content =
        \\address.street = REDACT
        \\address.city = REDACT
        \\address.state = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"address":{"street":"123 Main St","city":"Springfield","state":"IL"}}
    ;

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"address":{"street":"[REDACTED]","city":"[REDACTED]","state":"IL"}}
    , output);
}

test "json_redactor - non-string REDACT becomes null" {
    const schema_content =
        \\schema.default = KEEP
        \\age = REDACT
        \\active = REDACT
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"age":42,"active":true,"name":"visible"}
    ;

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"age":null,"active":null,"name":"visible"}
    , output);
}

test "json_redactor - default action SCAN without scan_ctx passes through" {
    const schema_content =
        \\schema.default = SCAN
        \\safe_field = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"safe_field":"hello","other":"world"}
    ;

    // No scan context provided — SCAN fields pass through
    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"safe_field":"hello","other":"world"}
    , output);
}

test "json_redactor - empty object" {
    const schema_content =
        \\patient_name = REDACT
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input = "{}";

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings("{}", output);
}

test "json_redactor - empty input returns empty" {
    var schema = Schema.init(std.testing.allocator);
    defer schema.deinit();

    const output = try redactJson("", &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings("", output);
}

test "json_redactor - null value with KEEP" {
    const schema_content =
        \\schema.default = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"field":null}
    ;

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"field":null}
    , output);
}

test "json_redactor - escaped string value" {
    const schema_content =
        \\schema.default = KEEP
        \\secret = REDACT
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"secret":"line1\nline2","visible":"ok"}
    ;

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"secret":"[REDACTED]","visible":"ok"}
    , output);
}

test "json_redactor - array of primitives" {
    const schema_content =
        \\schema.default = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"tags":["alpha","beta","gamma"]}
    ;

    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"tags":["alpha","beta","gamma"]}
    , output);
}

test "json_redactor - SCAN with callback" {
    const ScanTestCtx = struct {
        fn doScan(input_val: []const u8, _: []const u8, _: *anyopaque, alloc: std.mem.Allocator) ![]u8 {
            // Simple test: replace "SSN 123-45-6789" with "SSN ***-**-****"
            if (std.mem.indexOf(u8, input_val, "123-45-6789")) |pos| {
                var buf = try alloc.alloc(u8, input_val.len - 11 + 13);
                @memcpy(buf[0..pos], input_val[0..pos]);
                @memcpy(buf[pos .. pos + 13], "***-**-****  ");
                const rest_start = pos + 11;
                if (rest_start < input_val.len) {
                    @memcpy(buf[pos + 13 ..], input_val[rest_start..]);
                }
                return buf;
            }
            return try alloc.dupe(u8, input_val);
        }
    };

    const schema_content =
        \\safe = KEEP
        \\data = SCAN
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    var dummy: u8 = 0;
    const scan_ctx = ScanContext{
        .scan_fn = &ScanTestCtx.doScan,
        .ctx_ptr = @ptrCast(&dummy),
    };

    const input =
        \\{"safe":"hello","data":"no SSN here"}
    ;

    const output = try redactJson(input, &schema, null, scan_ctx, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"safe":"hello","data":"no SSN here"}
    , output);
}

test "json_redactor - mixed actions comprehensive" {
    const schema_content =
        \\schema.default = KEEP
        \\patient_name = REDACT
        \\dob = REDACT
        \\visit_date = KEEP
        \\notes = SCAN
        \\address.street = REDACT
        \\address.zip = REDACT
        \\address.state = KEEP
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    const input =
        \\{"patient_name":"Jane","dob":"1990-01-01","visit_date":"2024-03-07","notes":"healthy","address":{"street":"456 Oak Ave","zip":"62704","state":"IL"},"id":12345}
    ;

    // No scan_ctx — SCAN fields pass through
    const output = try redactJson(input, &schema, null, null, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(
        \\{"patient_name":"[REDACTED]","dob":"[REDACTED]","visit_date":"2024-03-07","notes":"healthy","address":{"street":"[REDACTED]","zip":"[REDACTED]","state":"IL"},"id":12345}
    , output);
}

test "json_redactor - SCAN callback performs replacement" {
    const ScanUpperCtx = struct {
        fn doScan(input_val: []const u8, _: []const u8, _: *anyopaque, alloc: std.mem.Allocator) ![]u8 {
            // Test adapter: uppercase the input to prove the callback ran
            var buf = try alloc.alloc(u8, input_val.len);
            for (input_val, 0..) |c, i| {
                buf[i] = std.ascii.toUpper(c);
            }
            return buf;
        }
    };

    const schema_content =
        \\safe = KEEP
        \\data = SCAN
    ;

    var schema = try Schema.parseContent(schema_content, std.testing.allocator);
    defer schema.deinit();

    var dummy: u8 = 0;
    const scan_ctx = ScanContext{
        .scan_fn = &ScanUpperCtx.doScan,
        .ctx_ptr = @ptrCast(&dummy),
    };

    const input =
        \\{"safe":"hello","data":"sensitive info"}
    ;

    const output = try redactJson(input, &schema, null, scan_ctx, std.testing.allocator);
    defer std.testing.allocator.free(output);

    // "data" field value should be uppercased by the scan callback
    try std.testing.expectEqualStrings(
        \\{"safe":"hello","data":"SENSITIVE INFO"}
    , output);
}
