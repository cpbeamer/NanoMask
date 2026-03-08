const std = @import("std");
const http = std.http;

pub const BodyPolicy = enum {
    redact,
    bypass,
    reject,
};

pub const UnsupportedBodyBehavior = enum {
    bypass,
    reject,

    pub fn parse(value: []const u8) !UnsupportedBodyBehavior {
        if (std.ascii.eqlIgnoreCase(value, "bypass")) return .bypass;
        if (std.ascii.eqlIgnoreCase(value, "reject")) return .reject;
        return error.InvalidUnsupportedBodyBehavior;
    }

    pub fn asBodyPolicy(self: UnsupportedBodyBehavior) BodyPolicy {
        return switch (self) {
            .bypass => .bypass,
            .reject => .reject,
        };
    }
};

pub const BodyKind = enum {
    none,
    json,
    ndjson,
    text,
    bypass,
    unsupported,

    pub fn supportsInlineTransform(self: BodyKind) bool {
        return switch (self) {
            .json, .ndjson, .text => true,
            else => false,
        };
    }

    pub fn supportsSchemaJson(self: BodyKind) bool {
        return self == .json;
    }

    pub fn supportsJsonResponseTransform(self: BodyKind) bool {
        return self == .json;
    }
};

pub const Classification = struct {
    policy: BodyPolicy,
    kind: BodyKind,
    content_type: ?[]const u8,
    content_encoding: http.ContentEncoding,
};

pub fn classifyRequest(
    has_body: bool,
    content_type: ?[]const u8,
    content_encoding: http.ContentEncoding,
    unsupported_behavior: UnsupportedBodyBehavior,
) Classification {
    if (!has_body) {
        return .{
            .policy = .bypass,
            .kind = .none,
            .content_type = content_type,
            .content_encoding = content_encoding,
        };
    }

    const kind = classifyContentType(content_type);
    return .{
        .policy = classifyTransformPolicy(kind, content_encoding, unsupported_behavior),
        .kind = kind,
        .content_type = content_type,
        .content_encoding = content_encoding,
    };
}

pub fn classifyResponse(
    has_body: bool,
    content_type: ?[]const u8,
    content_encoding: http.ContentEncoding,
    transform_required: bool,
    unsupported_behavior: UnsupportedBodyBehavior,
) Classification {
    if (!has_body) {
        return .{
            .policy = .bypass,
            .kind = .none,
            .content_type = content_type,
            .content_encoding = content_encoding,
        };
    }

    const kind = classifyContentType(content_type);
    return .{
        .policy = if (transform_required)
            classifyTransformPolicy(kind, content_encoding, unsupported_behavior)
        else
            .bypass,
        .kind = kind,
        .content_type = content_type,
        .content_encoding = content_encoding,
    };
}

pub fn contentTypeForLog(content_type: ?[]const u8) []const u8 {
    return content_type orelse "-";
}

pub fn contentEncodingForLog(content_encoding: http.ContentEncoding) []const u8 {
    return @tagName(content_encoding);
}

fn classifyTransformPolicy(
    kind: BodyKind,
    content_encoding: http.ContentEncoding,
    unsupported_behavior: UnsupportedBodyBehavior,
) BodyPolicy {
    return switch (kind) {
        .json, .ndjson, .text => if (content_encoding == .identity)
            .redact
        else
            unsupported_behavior.asBodyPolicy(),
        .bypass => .bypass,
        .unsupported => unsupported_behavior.asBodyPolicy(),
        .none => .bypass,
    };
}

pub fn classifyContentType(content_type: ?[]const u8) BodyKind {
    const raw = content_type orelse return .unsupported;
    const media_type = trimMediaType(raw);
    if (media_type.len == 0) return .unsupported;

    if (isJsonLike(media_type)) return .json;
    if (std.ascii.eqlIgnoreCase(media_type, "application/x-ndjson")) return .ndjson;
    if (isTextLike(media_type)) return .text;
    if (isBypassType(media_type)) return .bypass;
    return .unsupported;
}

fn trimMediaType(raw: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, raw, ';') orelse raw.len;
    return std.mem.trim(u8, raw[0..end], " \t");
}

fn isJsonLike(media_type: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(media_type, "application/json")) return true;
    return asciiStartsWithIgnoreCase(media_type, "application/") and
        asciiEndsWithIgnoreCase(media_type, "+json");
}

fn isTextLike(media_type: []const u8) bool {
    return asciiStartsWithIgnoreCase(media_type, "text/");
}

fn isBypassType(media_type: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(media_type, "multipart/form-data")) return true;
    if (std.ascii.eqlIgnoreCase(media_type, "application/octet-stream")) return true;
    if (std.ascii.eqlIgnoreCase(media_type, "application/pdf")) return true;
    if (asciiStartsWithIgnoreCase(media_type, "image/")) return true;
    if (asciiStartsWithIgnoreCase(media_type, "audio/")) return true;
    if (asciiStartsWithIgnoreCase(media_type, "video/")) return true;
    return false;
}

fn asciiStartsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    if (haystack.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn asciiEndsWithIgnoreCase(haystack: []const u8, suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - suffix.len ..], suffix);
}

test "classifyRequest redacts json bodies" {
    const result = classifyRequest(true, "application/json; charset=utf-8", .identity, .reject);
    try std.testing.expectEqual(BodyPolicy.redact, result.policy);
    try std.testing.expectEqual(BodyKind.json, result.kind);
}

test "classifyRequest bypasses known binary types" {
    const result = classifyRequest(true, "application/pdf", .identity, .reject);
    try std.testing.expectEqual(BodyPolicy.bypass, result.policy);
    try std.testing.expectEqual(BodyKind.bypass, result.kind);
}

test "classifyRequest rejects unsupported request types when configured" {
    const result = classifyRequest(true, "application/xml", .identity, .reject);
    try std.testing.expectEqual(BodyPolicy.reject, result.policy);
    try std.testing.expectEqual(BodyKind.unsupported, result.kind);
}

test "classifyRequest bypasses encoded json when configured" {
    const result = classifyRequest(true, "application/vnd.api+json", .gzip, .bypass);
    try std.testing.expectEqual(BodyPolicy.bypass, result.policy);
    try std.testing.expectEqual(BodyKind.json, result.kind);
}

test "classifyResponse bypasses when no transform is needed" {
    const result = classifyResponse(true, "text/plain", .identity, false, .reject);
    try std.testing.expectEqual(BodyPolicy.bypass, result.policy);
    try std.testing.expectEqual(BodyKind.text, result.kind);
}

test "classifyResponse redacts json when transforms are needed" {
    const result = classifyResponse(true, "application/problem+json", .identity, true, .bypass);
    try std.testing.expectEqual(BodyPolicy.redact, result.policy);
    try std.testing.expectEqual(BodyKind.json, result.kind);
}
