const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const harness = @import("e2e_harness.zig");
const http_util = @import("../net/http_util.zig");

pub const CheckStatus = enum {
    pass,
    fail,
    not_applicable,
};

pub const FlowStatus = enum {
    pass,
    fail,
};

pub const FlowChecks = struct {
    request_header_fidelity: CheckStatus = .not_applicable,
    body_mutation: CheckStatus = .not_applicable,
    response_header_fidelity: CheckStatus = .not_applicable,
    streaming: CheckStatus = .not_applicable,
    path_query_fidelity: CheckStatus = .not_applicable,
    /// Measured first-token latency for streaming flows (null = not measured).
    first_token_latency_ms: ?u64 = null,
};

pub const FlowId = enum {
    openai_json,
    openai_sse,
    anthropic_sse,
    azure_openai,
    generic_json_rest,
    litellm_proxy_headers,
    // NMV3-014: edge-case flows
    anthropic_long_session,
    compressed_response_bypass,
    buffered_hash_response,
};

pub const FlowResult = struct {
    flow_id: FlowId,
    id: []const u8,
    label: []const u8,
    vendor: []const u8,
    request_method: []const u8,
    request_target: []const u8,
    checks: FlowChecks = .{},
    status: FlowStatus = .pass,
    failure_reason: ?[]u8 = null,

    pub fn deinit(self: *FlowResult, allocator: std.mem.Allocator) void {
        if (self.failure_reason) |reason| allocator.free(reason);
    }

    pub fn expectPass(self: FlowResult) !void {
        if (self.status == .pass) return;
        std.debug.print("compatibility flow {s} failed: {s}\n", .{
            self.id,
            self.failure_reason orelse "unknown",
        });
        return error.TestUnexpectedResult;
    }

    pub fn expectNoUnexpectedRegression(self: FlowResult) !void {
        if (!hasUnexpectedRegression(self)) return;
        std.debug.print("compatibility flow {s} regressed: {s}\n", .{
            self.id,
            self.failure_reason orelse "unknown",
        });
        return error.TestUnexpectedResult;
    }
};

const FlowDefinition = struct {
    id: FlowId,
    key: []const u8,
    label: []const u8,
    vendor: []const u8,
    method: http.Method,
    target: []const u8,
};

const flow_definitions = [_]FlowDefinition{
    .{
        .id = .openai_json,
        .key = "openai_json",
        .label = "OpenAI-compatible JSON",
        .vendor = "OpenAI-compatible",
        .method = .POST,
        .target = "/v1/chat/completions",
    },
    .{
        .id = .openai_sse,
        .key = "openai_sse",
        .label = "OpenAI-compatible SSE streaming",
        .vendor = "OpenAI-compatible",
        .method = .POST,
        .target = "/v1/chat/completions",
    },
    .{
        .id = .anthropic_sse,
        .key = "anthropic_sse",
        .label = "Anthropic SSE streaming",
        .vendor = "Anthropic-style",
        .method = .POST,
        .target = "/v1/messages",
    },
    .{
        .id = .azure_openai,
        .key = "azure_openai",
        .label = "Azure OpenAI path/query",
        .vendor = "Azure OpenAI-style",
        .method = .POST,
        .target = "/openai/deployments/gpt-4o-mini/chat/completions?api-version=2024-10-21",
    },
    .{
        .id = .generic_json_rest,
        .key = "generic_json_rest",
        .label = "Generic JSON REST API",
        .vendor = "Generic REST",
        .method = .POST,
        .target = "/v1/patients/42?include=notes&expand=coverage",
    },
    .{
        .id = .litellm_proxy_headers,
        .key = "litellm_proxy_headers",
        .label = "LiteLLM-style proxy headers",
        .vendor = "LiteLLM-style",
        .method = .POST,
        .target = "/v1/chat/completions",
    },
    // NMV3-014: edge-case flows
    .{
        .id = .anthropic_long_session,
        .key = "anthropic_long_session",
        .label = "Anthropic long-lived SSE session",
        .vendor = "Anthropic-style",
        .method = .POST,
        .target = "/v1/messages",
    },
    .{
        .id = .compressed_response_bypass,
        .key = "compressed_response_bypass",
        .label = "Compressed response bypass",
        .vendor = "Generic REST",
        .method = .POST,
        .target = "/v1/data",
    },
    .{
        .id = .buffered_hash_response,
        .key = "buffered_hash_response",
        .label = "HASH-mode buffered response",
        .vendor = "OpenAI-compatible",
        .method = .POST,
        .target = "/v1/chat/completions",
    },
};

fn findDefinition(id: FlowId) *const FlowDefinition {
    for (&flow_definitions) |*definition| {
        if (definition.id == id) return definition;
    }
    unreachable;
}

fn recordFailure(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    comptime fmt: []const u8,
    args: anytype,
) !void {
    if (report.failure_reason != null) return;
    report.failure_reason = try std.fmt.allocPrint(allocator, fmt, args);
}

fn requestLine(head: []const u8) ?[]const u8 {
    const line_end = std.mem.indexOf(u8, head, "\r\n") orelse return null;
    return head[0..line_end];
}

fn requestMethod(head: []const u8) ?[]const u8 {
    const line = requestLine(head) orelse return null;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    return it.next();
}

fn requestTarget(head: []const u8) ?[]const u8 {
    const line = requestLine(head) orelse return null;
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    _ = it.next() orelse return null;
    return it.next();
}

fn checkMethodEquals(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    head: []const u8,
    expected: []const u8,
) !bool {
    const actual = requestMethod(head) orelse {
        try recordFailure(allocator, report, "missing request line in upstream capture", .{});
        return false;
    };
    if (std.mem.eql(u8, actual, expected)) return true;
    try recordFailure(allocator, report, "expected request method {s}, got {s}", .{ expected, actual });
    return false;
}

fn checkTargetEquals(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    head: []const u8,
    expected: []const u8,
) !bool {
    const actual = requestTarget(head) orelse {
        try recordFailure(allocator, report, "missing request target in upstream capture", .{});
        return false;
    };
    if (std.mem.eql(u8, actual, expected)) return true;
    try recordFailure(allocator, report, "expected request target {s}, got {s}", .{ expected, actual });
    return false;
}

fn checkHeaderEquals(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    head: []const u8,
    header_name: []const u8,
    expected: []const u8,
) !bool {
    const actual = http_util.findHeader(head, header_name) orelse {
        try recordFailure(allocator, report, "missing header {s}", .{header_name});
        return false;
    };
    if (std.mem.eql(u8, actual, expected)) return true;
    try recordFailure(allocator, report, "expected header {s}={s}, got {s}", .{ header_name, expected, actual });
    return false;
}

fn checkContains(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    haystack: []const u8,
    needle: []const u8,
    context: []const u8,
) !bool {
    if (std.mem.indexOf(u8, haystack, needle) != null) return true;
    try recordFailure(allocator, report, "{s} is missing expected text {s}", .{ context, needle });
    return false;
}

fn checkNotContains(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    haystack: []const u8,
    needle: []const u8,
    context: []const u8,
) !bool {
    if (std.mem.indexOf(u8, haystack, needle) == null) return true;
    try recordFailure(allocator, report, "{s} still contains forbidden text {s}", .{ context, needle });
    return false;
}

fn checkBodyEquals(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    actual: []const u8,
    expected: []const u8,
    context: []const u8,
) !bool {
    if (std.mem.eql(u8, actual, expected)) return true;
    try recordFailure(allocator, report, "{s} body did not match the upstream payload", .{context});
    return false;
}

fn checkStatusEquals(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    actual: http.Status,
    expected: http.Status,
    context: []const u8,
) !bool {
    if (actual == expected) return true;
    try recordFailure(allocator, report, "{s} returned HTTP {d} instead of {d}", .{
        context,
        @intFromEnum(actual),
        @intFromEnum(expected),
    });
    return false;
}

fn checkStreaming(
    allocator: std.mem.Allocator,
    report: *FlowResult,
    result: harness.RoundTripResult,
    expected_body: []const u8,
    max_first_chunk_latency_ms: u64,
    min_total_latency_ms: u64,
) !bool {
    var ok = true;

    if (!std.mem.eql(u8, result.client_body, expected_body)) {
        ok = false;
        try recordFailure(allocator, report, "streamed client body did not match the upstream event stream", .{});
    }

    if (result.first_chunk_latency_ns == null) {
        ok = false;
        try recordFailure(allocator, report, "streaming flow never produced a first chunk", .{});
    } else if (result.first_chunk_latency_ns.? >= max_first_chunk_latency_ms * std.time.ns_per_ms) {
        ok = false;
        try recordFailure(allocator, report, "first streamed chunk arrived too late ({d} ns)", .{
            result.first_chunk_latency_ns.?,
        });
    }

    if (result.client_chunk_count == 0) {
        ok = false;
        try recordFailure(allocator, report, "streaming flow produced no readable client chunks", .{});
    } else if (result.first_chunk_latency_ns != null and
        result.total_response_latency_ns <= result.first_chunk_latency_ns.? + (20 * std.time.ns_per_ms))
    {
        ok = false;
        try recordFailure(allocator, report, "streaming flow collapsed into {d} client chunk(s)", .{
            result.client_chunk_count,
        });
    }

    if (result.total_response_latency_ns < min_total_latency_ms * std.time.ns_per_ms) {
        ok = false;
        try recordFailure(allocator, report, "stream completed too quickly to prove incremental flush behavior ({d} ns)", .{
            result.total_response_latency_ns,
        });
    }

    return ok;
}

fn evaluateOpenAi(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer sk-openai-test" },
        .{ .name = "OpenAI-Beta", .value = "assistants=v2" },
        .{ .name = "x-request-id", .value = "req-openai-client-1" },
        .{ .name = "Cookie", .value = "session=openai-sess-1; _ga=GA1.2.abc" },
        .{ .name = "Idempotency-Key", .value = "idem-openai-001" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "x-request-id", .value = "req-openai-upstream-1" },
        .{ .name = "openai-processing-ms", .value = "14" },
        .{ .name = "Cache-Control", .value = "no-store" },
        .{ .name = "Set-Cookie", .value = "session=openai-sess-2; Path=/; HttpOnly" },
        .{ .name = "x-ratelimit-remaining-requests", .value = "59" },
    };
    const request_body =
        \\{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Patient SSN 123-45-6789 needs follow up"}]}
    ;
    const response_body =
        \\{"id":"chatcmpl-test-123","object":"chat.completion","choices":[{"message":{"role":"assistant","content":"Acknowledged"}}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_response = response_body,
        .upstream_content_type = "application/json",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    var route_ok = true;
    if (!(try checkMethodEquals(allocator, report, result.upstream_head, @tagName(definition.method)))) route_ok = false;
    if (!(try checkTargetEquals(allocator, report, result.upstream_head, definition.target))) route_ok = false;
    report.checks.path_query_fidelity = if (route_ok) .pass else .fail;

    var request_headers_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Authorization", "Bearer sk-openai-test"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "OpenAI-Beta", "assistants=v2"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-request-id", "req-openai-client-1"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Accept-Encoding", "identity"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Cookie", "session=openai-sess-1; _ga=GA1.2.abc"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Idempotency-Key", "idem-openai-001"))) request_headers_ok = false;
    report.checks.request_header_fidelity = if (request_headers_ok) .pass else .fail;

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "OpenAI upstream request"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "OpenAI upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-request-id", "req-openai-upstream-1"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "openai-processing-ms", "14"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "application/json"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Set-Cookie", "session=openai-sess-2; Path=/; HttpOnly"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-ratelimit-remaining-requests", "59"))) response_ok = false;
    if (!(try checkBodyEquals(allocator, report, result.client_body, response_body, "OpenAI client response"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;
}

fn evaluateOpenAiSse(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer sk-openai-stream-test" },
        .{ .name = "Accept", .value = "text/event-stream" },
        .{ .name = "x-request-id", .value = "req-openai-stream-1" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "x-request-id", .value = "req-openai-stream-resp-1" },
        .{ .name = "openai-processing-ms", .value = "42" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    };
    const stream_chunks = [_][]const u8{
        "data: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n",
        "data: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n",
        "data: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n",
        "data: [DONE]\n\n",
    };
    const expected_stream =
        "data: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n" ++
        "data: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"delta\":{\"content\":\"Hello\"}}]}\n\n" ++
        "data: {\"id\":\"chatcmpl-s1\",\"choices\":[{\"delta\":{\"content\":\" there\"}}]}\n\n" ++
        "data: [DONE]\n\n";
    const request_body =
        \\{"model":"gpt-4o-mini","stream":true,"messages":[{"role":"user","content":"Patient SSN 123-45-6789 needs triage"}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_stream_chunks = &stream_chunks,
        .upstream_inter_chunk_delay_ms = 75,
        .upstream_content_type = "text/event-stream",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    var route_ok = true;
    if (!(try checkMethodEquals(allocator, report, result.upstream_head, @tagName(definition.method)))) route_ok = false;
    if (!(try checkTargetEquals(allocator, report, result.upstream_head, definition.target))) route_ok = false;
    report.checks.path_query_fidelity = if (route_ok) .pass else .fail;

    var request_headers_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Authorization", "Bearer sk-openai-stream-test"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Accept", "text/event-stream"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-request-id", "req-openai-stream-1"))) request_headers_ok = false;
    report.checks.request_header_fidelity = if (request_headers_ok) .pass else .fail;

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "OpenAI SSE upstream request"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "OpenAI SSE upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-request-id", "req-openai-stream-resp-1"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "openai-processing-ms", "42"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "text/event-stream"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Transfer-Encoding", "chunked"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;

    const streaming_ok = try checkStreaming(
        allocator,
        report,
        result,
        expected_stream,
        200,
        120,
    );
    report.checks.streaming = if (streaming_ok) .pass else .fail;

    // Record first-token latency for the compatibility matrix artifact
    if (result.first_chunk_latency_ns) |ns| {
        report.checks.first_token_latency_ms = ns / std.time.ns_per_ms;
    }
}

fn evaluateAnthropic(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "x-api-key", .value = "anthropic-test-key" },
        .{ .name = "anthropic-version", .value = "2023-06-01" },
        .{ .name = "Accept", .value = "text/event-stream" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "anthropic-request-id", .value = "msg_req_123" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    };
    const stream_chunks = [_][]const u8{
        "event: message_start\ndata: {\"type\":\"message_start\"}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    };
    const expected_stream =
        "event: message_start\ndata: {\"type\":\"message_start\"}\n\n" ++
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"Hello\"}}\n\n" ++
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    const request_body =
        \\{"model":"claude-3-5-sonnet","stream":true,"messages":[{"role":"user","content":"Patient SSN 123-45-6789 needs triage"}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_stream_chunks = &stream_chunks,
        .upstream_inter_chunk_delay_ms = 75,
        .upstream_content_type = "text/event-stream",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    var route_ok = true;
    if (!(try checkMethodEquals(allocator, report, result.upstream_head, @tagName(definition.method)))) route_ok = false;
    if (!(try checkTargetEquals(allocator, report, result.upstream_head, definition.target))) route_ok = false;
    report.checks.path_query_fidelity = if (route_ok) .pass else .fail;

    var request_headers_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-api-key", "anthropic-test-key"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "anthropic-version", "2023-06-01"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Accept", "text/event-stream"))) request_headers_ok = false;
    report.checks.request_header_fidelity = if (request_headers_ok) .pass else .fail;

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "Anthropic upstream request"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "Anthropic upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "anthropic-request-id", "msg_req_123"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Cache-Control", "no-cache"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "text/event-stream"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Transfer-Encoding", "chunked"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;

    report.checks.streaming = if (try checkStreaming(
        allocator,
        report,
        result,
        expected_stream,
        200,
        120,
    )) .pass else .fail;

    // Per-event structure validation: verify each SSE event delimiter survived
    // intact through the proxy rather than being collapsed or corrupted.
    if (report.checks.streaming == .pass) {
        var events_ok = true;
        if (!(try checkContains(allocator, report, result.client_body, "event: message_start\n", "Anthropic SSE event delimiters"))) events_ok = false;
        if (!(try checkContains(allocator, report, result.client_body, "event: content_block_delta\n", "Anthropic SSE event delimiters"))) events_ok = false;
        if (!(try checkContains(allocator, report, result.client_body, "event: message_stop\n", "Anthropic SSE event delimiters"))) events_ok = false;
        if (!events_ok) report.checks.streaming = .fail;
    }

    // Record first-token latency for the compatibility matrix artifact
    if (result.first_chunk_latency_ns) |ns| {
        report.checks.first_token_latency_ms = ns / std.time.ns_per_ms;
    }
}

fn evaluateAzureOpenAi(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "api-key", .value = "azure-api-key-test" },
        .{ .name = "x-ms-client-request-id", .value = "azure-trace-42" },
        .{ .name = "Accept", .value = "application/json" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "apim-request-id", .value = "azure-resp-001" },
        .{ .name = "x-ms-region", .value = "eastus" },
    };
    const request_body =
        \\{"messages":[{"role":"user","content":"SSN 123-45-6789 is in this prompt"}],"temperature":0}
    ;
    const response_body =
        \\{"id":"azure-chatcmpl-001","choices":[{"message":{"role":"assistant","content":"Processed"}}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_response = response_body,
        .upstream_content_type = "application/json",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    var route_ok = true;
    if (!(try checkMethodEquals(allocator, report, result.upstream_head, @tagName(definition.method)))) route_ok = false;
    if (!(try checkTargetEquals(allocator, report, result.upstream_head, definition.target))) route_ok = false;
    report.checks.path_query_fidelity = if (route_ok) .pass else .fail;

    var request_headers_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "api-key", "azure-api-key-test"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-ms-client-request-id", "azure-trace-42"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Accept", "application/json"))) request_headers_ok = false;
    report.checks.request_header_fidelity = if (request_headers_ok) .pass else .fail;

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "Azure upstream request"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "Azure upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "apim-request-id", "azure-resp-001"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-ms-region", "eastus"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "application/json"))) response_ok = false;
    if (!(try checkBodyEquals(allocator, report, result.client_body, response_body, "Azure client response"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;
}

fn evaluateGenericJsonRest(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer generic-api-token" },
        .{ .name = "If-Match", .value = "\"patient-42-v3\"" },
        .{ .name = "Accept-Language", .value = "en-US" },
        .{ .name = "x-request-id", .value = "generic-rest-99" },
        .{ .name = "Cookie", .value = "jwt=eyJhbGc; _csrf=tok123" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "ETag", .value = "\"patient-42-v4\"" },
        .{ .name = "Cache-Control", .value = "private, max-age=30" },
        .{ .name = "x-request-id", .value = "generic-rest-99" },
    };
    const request_body =
        \\{"patient_note":"Please scrub SSN 123-45-6789 before sending","status":"pending"}
    ;
    const response_body =
        \\{"id":42,"status":"updated","version":4}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_response = response_body,
        .upstream_content_type = "application/json",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    var route_ok = true;
    if (!(try checkMethodEquals(allocator, report, result.upstream_head, @tagName(definition.method)))) route_ok = false;
    if (!(try checkTargetEquals(allocator, report, result.upstream_head, definition.target))) route_ok = false;
    report.checks.path_query_fidelity = if (route_ok) .pass else .fail;

    var request_headers_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Authorization", "Bearer generic-api-token"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "If-Match", "\"patient-42-v3\""))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Accept-Language", "en-US"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-request-id", "generic-rest-99"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Cookie", "jwt=eyJhbGc; _csrf=tok123"))) request_headers_ok = false;
    report.checks.request_header_fidelity = if (request_headers_ok) .pass else .fail;

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "Generic REST upstream request"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "Generic REST upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "ETag", "\"patient-42-v4\""))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Cache-Control", "private, max-age=30"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-request-id", "generic-rest-99"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "application/json"))) response_ok = false;
    if (!(try checkBodyEquals(allocator, report, result.client_body, response_body, "Generic REST client response"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;
}

fn evaluateLiteLlm(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer litellm-gateway-token" },
        .{ .name = "x-litellm-api-key", .value = "litellm-upstream-key" },
        .{ .name = "x-litellm-tags", .value = "pilot,phi" },
        .{ .name = "x-litellm-metadata", .value = "{\"team\":\"security\"}" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "x-litellm-model-id", .value = "gpt-4o-mini" },
        .{ .name = "x-litellm-cache-key", .value = "cache-123" },
    };
    const request_body =
        \\{"model":"openai/gpt-4o-mini","messages":[{"role":"user","content":"Mask SSN 123-45-6789 before egress"}]}
    ;
    const response_body =
        \\{"id":"litellm-001","choices":[{"message":{"role":"assistant","content":"Done"}}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_response = response_body,
        .upstream_content_type = "application/json",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    var route_ok = true;
    if (!(try checkMethodEquals(allocator, report, result.upstream_head, @tagName(definition.method)))) route_ok = false;
    if (!(try checkTargetEquals(allocator, report, result.upstream_head, definition.target))) route_ok = false;
    report.checks.path_query_fidelity = if (route_ok) .pass else .fail;

    var request_headers_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "Authorization", "Bearer litellm-gateway-token"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-litellm-api-key", "litellm-upstream-key"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-litellm-tags", "pilot,phi"))) request_headers_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.upstream_head, "x-litellm-metadata", "{\"team\":\"security\"}"))) request_headers_ok = false;
    report.checks.request_header_fidelity = if (request_headers_ok) .pass else .fail;

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "LiteLLM upstream request"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "LiteLLM upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-litellm-model-id", "gpt-4o-mini"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-litellm-cache-key", "cache-123"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "application/json"))) response_ok = false;
    if (!(try checkBodyEquals(allocator, report, result.client_body, response_body, "LiteLLM client response"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;
}

// ===========================================================================
// NMV3-014: Edge-case evaluator functions
// ===========================================================================

fn evaluateAnthropicLongSession(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const request_headers = [_]http.Header{
        .{ .name = "x-api-key", .value = "anthropic-long-session-key" },
        .{ .name = "anthropic-version", .value = "2023-06-01" },
        .{ .name = "Accept", .value = "text/event-stream" },
    };
    const response_headers = [_]http.Header{
        .{ .name = "anthropic-request-id", .value = "msg_long_session_1" },
        .{ .name = "Cache-Control", .value = "no-cache" },
    };

    // 10-event long-lived stream with mixed Anthropic event types
    const stream_chunks = [_][]const u8{
        "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_01\"}}\n\n",
        "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"The \"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"patient \"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"record \"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"shows \"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"normal \"}}\n\n",
        "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"results.\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    };

    var expected_buf = std.ArrayListUnmanaged(u8).empty;
    defer expected_buf.deinit(allocator);
    for (stream_chunks) |chunk| {
        try expected_buf.appendSlice(allocator, chunk);
    }

    const request_body =
        \\{"model":"claude-3-5-sonnet","stream":true,"max_tokens":1024,"messages":[{"role":"user","content":"Summarize patient chart SSN 123-45-6789"}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .request_extra_headers = &request_headers,
        .upstream_stream_chunks = &stream_chunks,
        .upstream_inter_chunk_delay_ms = 50,
        .upstream_content_type = "text/event-stream",
        .upstream_extra_headers = &response_headers,
    });
    defer result.deinit();

    // SSN should be redacted in upstream request
    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "Anthropic long session upstream"))) body_ok = false;
    if (!(try checkContains(allocator, report, result.upstream_body, "***-**-****", "Anthropic long session upstream"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    // Streaming fidelity: all 10 events should arrive incrementally.
    // 10 chunks × 50ms inter-chunk delay = ~500ms minimum. Allow 1500ms
    // ceiling to avoid flakiness under CI load.
    const streaming_ok = try checkStreaming(
        allocator,
        report,
        result,
        expected_buf.items,
        200,
        1500,
    );
    report.checks.streaming = if (streaming_ok) .pass else .fail;

    // Verify per-event structure: each event type delimiter survived intact
    if (report.checks.streaming == .pass) {
        var events_ok = true;
        if (!(try checkContains(allocator, report, result.client_body, "event: message_start\n", "long session event delimiters"))) events_ok = false;
        if (!(try checkContains(allocator, report, result.client_body, "event: content_block_start\n", "long session event delimiters"))) events_ok = false;
        if (!(try checkContains(allocator, report, result.client_body, "event: content_block_stop\n", "long session event delimiters"))) events_ok = false;
        if (!(try checkContains(allocator, report, result.client_body, "event: message_stop\n", "long session event delimiters"))) events_ok = false;
        if (!events_ok) report.checks.streaming = .fail;
    }

    if (result.first_chunk_latency_ns) |ns| {
        report.checks.first_token_latency_ms = ns / std.time.ns_per_ms;
    }
}

fn evaluateCompressedBypass(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    // A response with Content-Encoding: gzip should be forwarded to the client
    // untouched — the proxy bypasses the body rather than attempting to
    // decompress or inspect it. This tests Content-Encoding bypass policy,
    // not actual gzip decompression correctness.
    const request_body =
        \\{"query":"SELECT * FROM records WHERE ssn = '123-45-6789'"}
    ;
    // Opaque binary payload representing a real gzip body. The proxy must not
    // corrupt or inspect it; it should be forwarded byte-for-byte.
    const compressed_response = "FAKE_GZIP_PAYLOAD_1234567890";
    const response_headers = [_]http.Header{
        .{ .name = "Content-Encoding", .value = "gzip" },
        .{ .name = "x-custom-trace", .value = "compressed-test-1" },
    };

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .upstream_response = compressed_response,
        .upstream_content_type = "application/json",
        .upstream_extra_headers = &response_headers,
        .unsupported_response_body_behavior = .bypass,
    });
    defer result.deinit();

    // The compressed response body should be returned to the client unchanged
    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    if (!(try checkBodyEquals(allocator, report, result.client_body, compressed_response, "compressed bypass client response"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    // Content-Encoding should be forwarded to the client
    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Encoding", "gzip"))) response_ok = false;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "x-custom-trace", "compressed-test-1"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;
}

fn evaluateBufferedHash(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    const hasher_mod = @import("../schema/hasher.zig");
    const schema_mod = @import("../schema/schema.zig");

    // Set up a schema with a HASH field and a hasher
    var hasher = try hasher_mod.Hasher.init(null, allocator);
    defer hasher.deinit();

    // Schema uses INI-like format: key_path = ACTION
    const schema_content =
        \\schema.name = hash_test
        \\content = HASH
    ;
    var schema = try schema_mod.Schema.parseContent(schema_content, allocator);
    defer schema.deinit();

    const request_body =
        \\{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Patient SSN 123-45-6789 needs review"}]}
    ;
    // The upstream response contains a value that the HASH pipeline will pseudonymize
    // on the request path, then unhash on the response path
    const response_body =
        \\{"id":"chatcmpl-hash-1","choices":[{"message":{"role":"assistant","content":"Reviewed successfully"}}]}
    ;

    var result = try harness.roundTrip(allocator, request_body, .{
        .request_method = definition.method,
        .request_target = definition.target,
        .upstream_response = response_body,
        .upstream_content_type = "application/json",
        .schema = &schema,
        .hasher = &hasher,
    });
    defer result.deinit();

    var body_ok = true;
    if (!(try checkStatusEquals(allocator, report, result.status, .ok, definition.label))) body_ok = false;
    // SSN should be redacted in the upstream request
    if (!(try checkNotContains(allocator, report, result.upstream_body, "123-45-6789", "HASH upstream request"))) body_ok = false;
    report.checks.body_mutation = if (body_ok) .pass else .fail;

    // Response should be successfully unhashed and returned to client
    var response_ok = true;
    if (!(try checkHeaderEquals(allocator, report, result.client_head, "Content-Type", "application/json"))) response_ok = false;
    // The response body should be returned (the content field wasn't pseudonymized
    // since it's an output, so the body should match the upstream response)
    if (!(try checkContains(allocator, report, result.client_body, "Reviewed successfully", "HASH client response"))) response_ok = false;
    report.checks.response_header_fidelity = if (response_ok) .pass else .fail;
}

fn evaluateFlow(allocator: std.mem.Allocator, definition: FlowDefinition, report: *FlowResult) !void {
    switch (definition.id) {
        .openai_json => try evaluateOpenAi(allocator, definition, report),
        .openai_sse => try evaluateOpenAiSse(allocator, definition, report),
        .anthropic_sse => try evaluateAnthropic(allocator, definition, report),
        .azure_openai => try evaluateAzureOpenAi(allocator, definition, report),
        .generic_json_rest => try evaluateGenericJsonRest(allocator, definition, report),
        .litellm_proxy_headers => try evaluateLiteLlm(allocator, definition, report),
        // NMV3-014: edge-case flows
        .anthropic_long_session => try evaluateAnthropicLongSession(allocator, definition, report),
        .compressed_response_bypass => try evaluateCompressedBypass(allocator, definition, report),
        .buffered_hash_response => try evaluateBufferedHash(allocator, definition, report),
    }
}

fn finalizeStatus(report: *FlowResult) void {
    report.status = if (report.failure_reason == null) .pass else .fail;
}

pub fn hasUnexpectedRegression(report: FlowResult) bool {
    return report.status == .fail;
}

pub fn hasUnexpectedRegressions(results: []const FlowResult) bool {
    for (results) |report| {
        if (hasUnexpectedRegression(report)) return true;
    }
    return false;
}

pub fn runFlow(allocator: std.mem.Allocator, id: FlowId) !FlowResult {
    const definition = findDefinition(id);
    var report = FlowResult{
        .flow_id = definition.id,
        .id = definition.key,
        .label = definition.label,
        .vendor = definition.vendor,
        .request_method = @tagName(definition.method),
        .request_target = definition.target,
    };

    evaluateFlow(allocator, definition.*, &report) catch |err| {
        try recordFailure(allocator, &report, "flow execution error: {s}", .{@errorName(err)});
    };
    finalizeStatus(&report);
    return report;
}

pub fn runAll(allocator: std.mem.Allocator) ![]FlowResult {
    var results = std.ArrayListUnmanaged(FlowResult).empty;
    errdefer {
        for (results.items) |*report| report.deinit(allocator);
        results.deinit(allocator);
    }

    for (flow_definitions) |definition| {
        try results.append(allocator, try runFlow(allocator, definition.id));
    }
    return try results.toOwnedSlice(allocator);
}

pub fn freeResults(allocator: std.mem.Allocator, results: []FlowResult) void {
    for (results) |*report| report.deinit(allocator);
    allocator.free(results);
}

fn checkStatusString(status: CheckStatus) []const u8 {
    return switch (status) {
        .pass => "pass",
        .fail => "fail",
        .not_applicable => "not_applicable",
    };
}

fn flowStatusString(status: FlowStatus) []const u8 {
    return switch (status) {
        .pass => "pass",
        .fail => "fail",
    };
}

pub fn writeJson(writer: anytype, results: []const FlowResult) !void {
    var passed: usize = 0;
    var failed: usize = 0;
    for (results) |result| {
        switch (result.status) {
            .pass => passed += 1,
            .fail => failed += 1,
        }
    }

    try writer.writeAll("{\"suite\":\"nanomask_compatibility\",\"generated_at_unix\":");
    try writer.print("{d}", .{std.time.timestamp()});
    try writer.writeAll(",\"summary\":{\"total_flows\":");
    try writer.print("{d}", .{results.len});
    try writer.writeAll(",\"passed\":");
    try writer.print("{d}", .{passed});
    try writer.writeAll(",\"failed\":");
    try writer.print("{d}", .{failed});
    try writer.writeAll("},\"flows\":[");

    for (results, 0..) |result, index| {
        if (index > 0) try writer.writeAll(",");
        try writer.writeAll("{\"id\":");
        try std.json.Stringify.value(result.id, .{}, writer);
        try writer.writeAll(",\"label\":");
        try std.json.Stringify.value(result.label, .{}, writer);
        try writer.writeAll(",\"vendor\":");
        try std.json.Stringify.value(result.vendor, .{}, writer);
        try writer.writeAll(",\"request_method\":");
        try std.json.Stringify.value(result.request_method, .{}, writer);
        try writer.writeAll(",\"request_target\":");
        try std.json.Stringify.value(result.request_target, .{}, writer);
        try writer.writeAll(",\"status\":");
        try std.json.Stringify.value(flowStatusString(result.status), .{}, writer);
        try writer.writeAll(",\"checks\":{");
        try writer.writeAll("\"request_header_fidelity\":");
        try std.json.Stringify.value(checkStatusString(result.checks.request_header_fidelity), .{}, writer);
        try writer.writeAll(",\"body_mutation\":");
        try std.json.Stringify.value(checkStatusString(result.checks.body_mutation), .{}, writer);
        try writer.writeAll(",\"response_header_fidelity\":");
        try std.json.Stringify.value(checkStatusString(result.checks.response_header_fidelity), .{}, writer);
        try writer.writeAll(",\"streaming\":");
        try std.json.Stringify.value(checkStatusString(result.checks.streaming), .{}, writer);
        try writer.writeAll(",\"path_query_fidelity\":");
        try std.json.Stringify.value(checkStatusString(result.checks.path_query_fidelity), .{}, writer);
        try writer.writeAll(",\"first_token_latency_ms\":");
        if (result.checks.first_token_latency_ms) |latency| {
            try writer.print("{d}", .{latency});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("},\"failure_reason\":");
        if (result.failure_reason) |reason| {
            try std.json.Stringify.value(reason, .{}, writer);
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll("}");
    }

    try writer.writeAll("]}");
}

pub fn writeMarkdown(writer: anytype, results: []const FlowResult) !void {
    var passed: usize = 0;
    var failed: usize = 0;
    for (results) |result| {
        switch (result.status) {
            .pass => passed += 1,
            .fail => failed += 1,
        }
    }

    try writer.writeAll("# NanoMask Compatibility Matrix\n\n");

    const icon = if (failed == 0) "✅" else "❌";
    try writer.print("{s} **{d}/{d}** flows passing\n\n", .{ icon, passed, passed + failed });

    try writer.writeAll("| Flow | Vendor | Headers (Req) | Body | Headers (Resp) | Streaming | Path/Query | Latency | Status |\n");
    try writer.writeAll("|------|--------|:---:|:---:|:---:|:---:|:---:|---:|:---:|\n");

    for (results) |result| {
        try writer.print("| {s} | {s} | {s} | {s} | {s} | {s} | {s} | ", .{
            result.label,
            result.vendor,
            checkStatusIcon(result.checks.request_header_fidelity),
            checkStatusIcon(result.checks.body_mutation),
            checkStatusIcon(result.checks.response_header_fidelity),
            checkStatusIcon(result.checks.streaming),
            checkStatusIcon(result.checks.path_query_fidelity),
        });
        if (result.checks.first_token_latency_ms) |latency| {
            try writer.print("{d} ms", .{latency});
        } else {
            try writer.writeAll("—");
        }
        try writer.print(" | {s} |\n", .{if (result.status == .pass) "✅" else "❌"});
    }

    if (failed > 0) {
        try writer.writeAll("\n## Failures\n\n");
        for (results) |result| {
            if (result.status == .fail) {
                try writer.print("- **{s}**: {s}\n", .{
                    result.label,
                    result.failure_reason orelse "unknown",
                });
            }
        }
    }
}

fn checkStatusIcon(status: CheckStatus) []const u8 {
    return switch (status) {
        .pass => "✅",
        .fail => "❌",
        .not_applicable => "➖",
    };
}

test "compatibility matrix - OpenAI-compatible JSON flow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .openai_json);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - OpenAI SSE streaming flow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .openai_sse);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - Anthropic SSE flow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .anthropic_sse);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - Azure OpenAI flow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .azure_openai);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - generic JSON REST flow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .generic_json_rest);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - LiteLLM-style header flow" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .litellm_proxy_headers);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - Anthropic long-lived SSE session" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .anthropic_long_session);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - compressed response bypass" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .compressed_response_bypass);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - HASH-mode buffered response" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var report = try runFlow(allocator, .buffered_hash_response);
    defer report.deinit(allocator);
    try report.expectNoUnexpectedRegression();
}

test "compatibility matrix - any failed flow is a regression" {
    const allocator = std.testing.allocator;
    var report = FlowResult{
        .flow_id = .anthropic_sse,
        .id = "anthropic_sse",
        .label = "Anthropic SSE streaming",
        .vendor = "Anthropic-style",
        .request_method = "POST",
        .request_target = "/v1/messages",
        .checks = .{
            .request_header_fidelity = .fail,
            .body_mutation = .pass,
            .response_header_fidelity = .pass,
            .streaming = .fail,
            .path_query_fidelity = .pass,
        },
        .status = .fail,
        .failure_reason = try allocator.dupe(u8, "missing header x-api-key"),
    };
    defer report.deinit(allocator);

    try std.testing.expect(hasUnexpectedRegression(report));
}
