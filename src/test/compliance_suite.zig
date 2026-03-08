const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const harness = @import("e2e_harness.zig");
const body_policy = @import("../net/body_policy.zig");
const http_util = @import("../net/http_util.zig");
const schema_mod = @import("../schema/schema.zig");
const hasher_mod = @import("../schema/hasher.zig");

// ===========================================================================
// E2E Compliance Test Suite — Epic 9.2
//
// Each test sends a PII-laden payload through the full proxy pipeline
// and asserts that:
//   1. The mock upstream received a REDACTED body (zero PII leakage)
//   2. The test client received the expected response
// ===========================================================================

// ---------------------------------------------------------------------------
// 9.2.1 — SSN redaction round-trip
// ---------------------------------------------------------------------------
test "e2e compliance - SSN redaction" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Patient SSN is 123-45-6789 on file.";
    var result = try harness.roundTrip(allocator, body, .{});
    defer result.deinit();

    // Upstream must NOT see the original SSN
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "123-45-6789") == null);
    // Upstream should contain the redaction marker
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "***-**-****") != null);
}

// ---------------------------------------------------------------------------
// 9.2.2 — Entity name masking round-trip
// ---------------------------------------------------------------------------
test "e2e compliance - entity masking" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Dr. Jane Smith treated the patient today.";
    const names = [_][]const u8{"Jane Smith"};

    var result = try harness.roundTrip(allocator, body, .{
        .entity_names = &names,
        .upstream_response = "The response mentions Jane Smith again.",
    });
    defer result.deinit();

    // Upstream must NOT see the original entity name
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "Jane Smith") == null);
    // Client response should have the original name restored (unmasked)
    try std.testing.expect(std.mem.indexOf(u8, result.client_body, "Jane Smith") != null);
}

// ---------------------------------------------------------------------------
// 9.2.3 — Email redaction
// ---------------------------------------------------------------------------
test "e2e compliance - email redaction" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Contact: john.doe@hospital.org for details.";

    var result = try harness.roundTrip(allocator, body, .{
        .enable_email = true,
    });
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "john.doe@hospital.org") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "[EMAIL_REDACTED]") != null);
}

// ---------------------------------------------------------------------------
// 9.2.4 — Phone number redaction
// ---------------------------------------------------------------------------
test "e2e compliance - phone redaction" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Call (555) 123-4567 for appointments.";

    var result = try harness.roundTrip(allocator, body, .{
        .enable_phone = true,
    });
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "(555) 123-4567") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "[PHONE_REDACTED]") != null);
}

// ---------------------------------------------------------------------------
// 9.2.5 — Credit card redaction
// ---------------------------------------------------------------------------
test "e2e compliance - credit card redaction" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Payment card: 4111111111111111 on record.";

    var result = try harness.roundTrip(allocator, body, .{
        .enable_credit_card = true,
    });
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "4111111111111111") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "[CC_REDACTED]") != null);
}

// ---------------------------------------------------------------------------
// 9.2.6 — IP address redaction
// ---------------------------------------------------------------------------
test "e2e compliance - IPv4 redaction" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Server at 192.168.1.100 responded.";

    var result = try harness.roundTrip(allocator, body, .{
        .enable_ip = true,
    });
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "192.168.1.100") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "[IPV4_REDACTED]") != null);
}

// ---------------------------------------------------------------------------
// 9.2.7 — Healthcare identifier redaction
// ---------------------------------------------------------------------------
test "e2e compliance - healthcare MRN redaction" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Patient MRN: 1234567 admitted today. Diagnosis E11.65 confirmed.";

    var result = try harness.roundTrip(allocator, body, .{
        .enable_healthcare = true,
    });
    defer result.deinit();

    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "MRN: 1234567") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "[MRN_REDACTED]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "E11.65") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "[ICD10_REDACTED]") != null);
}

// ---------------------------------------------------------------------------
// 9.2.8 — Mixed payload (all PII types simultaneously)
// ---------------------------------------------------------------------------
test "e2e compliance - mixed PII payload" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body =
        \\Patient Jane Smith (SSN 123-45-6789) can be reached at
        \\jane.smith@hospital.org or (555) 123-4567. Card on file:
        \\4111111111111111. Server 10.0.0.1 logged the visit.
        \\MRN: 7654321, diagnosis E11.65.
    ;
    const names = [_][]const u8{"Jane Smith"};

    var result = try harness.roundTrip(allocator, body, .{
        .entity_names = &names,
        .enable_email = true,
        .enable_phone = true,
        .enable_credit_card = true,
        .enable_ip = true,
        .enable_healthcare = true,
    });
    defer result.deinit();

    // Zero PII leakage: none of the original values should appear upstream
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "Jane Smith") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "123-45-6789") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "jane.smith@hospital.org") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "(555) 123-4567") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "4111111111111111") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "10.0.0.1") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "MRN: 7654321") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "E11.65") == null);
}

// ---------------------------------------------------------------------------
// 9.2.9 — Clean passthrough (no PII)
// ---------------------------------------------------------------------------
test "e2e compliance - no PII passthrough" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "This text contains absolutely no personally identifiable information.";

    var result = try harness.roundTrip(allocator, body, .{
        .enable_email = true,
        .enable_phone = true,
        .enable_credit_card = true,
        .enable_ip = true,
        .enable_healthcare = true,
    });
    defer result.deinit();

    // Clean text should pass through unchanged
    try std.testing.expectEqualStrings(body, result.upstream_body);
}

// ---------------------------------------------------------------------------
// 9.2.10 — Schema-aware HASH mode round-trip
// ---------------------------------------------------------------------------
test "e2e compliance - schema HASH round-trip" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    // Build a schema via parseContent (the only public construction API)
    const schema_content =
        \\patient_name = REDACT
        \\internal_id = HASH
        \\notes = SCAN
    ;
    var schema_instance = try schema_mod.Schema.parseContent(schema_content, allocator);
    defer schema_instance.deinit();

    // Create a hasher with a valid 64-char hex key for determinism
    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var hasher_instance = try hasher_mod.Hasher.init(key_hex, allocator);
    defer hasher_instance.deinit();

    const body =
        \\{"patient_name":"John Doe","internal_id":"PT-99001","notes":"SSN is 999-88-7777","visit_date":"2026-03-08"}
    ;

    // Hash the value with the test key so we can build a realistic upstream response
    const pseudo_token = try hasher_instance.hash("PT-99001");
    defer allocator.free(pseudo_token);

    // Build upstream response containing the real PSEUDO_ token to exercise unhashing
    var resp_buf: [256]u8 = undefined;
    const upstream_resp = std.fmt.bufPrint(&resp_buf, "{{\"result\":\"processed\",\"id\":\"{s}\"}}", .{pseudo_token}) catch unreachable;

    var result = try harness.roundTrip(allocator, body, .{
        .schema = &schema_instance,
        .hasher = &hasher_instance,
        .upstream_response = upstream_resp,
        .upstream_content_type = "application/json",
    });
    defer result.deinit();

    // patient_name should be redacted (not the original)
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "John Doe") == null);

    // internal_id should be pseudonymised with PSEUDO_ prefix
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "PSEUDO_") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "PT-99001") == null);

    // SSN in notes (SCAN field) should be redacted
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "999-88-7777") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "***-**-****") != null);

    // Response-path unhashing: the client should see the original value restored
    try std.testing.expect(std.mem.indexOf(u8, result.client_body, "PT-99001") != null);
}

test "e2e compliance - PDF request bypass" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const payload = [_]u8{ 0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, 0x00, 0xff };

    var result = try harness.roundTrip(allocator, payload[0..], .{
        .request_content_type = "application/pdf",
    });
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, payload[0..], result.upstream_body);
    const accept_encoding = http_util.findHeader(result.upstream_head, "Accept-Encoding") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("identity", accept_encoding);
}

test "e2e compliance - unsupported request rejected" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var result = try harness.roundTrip(allocator, "<patient>Jane Smith</patient>", .{
        .request_content_type = "application/xml",
        .unsupported_request_body_behavior = .reject,
    });
    defer result.deinit();

    try std.testing.expectEqual(http.Status.unsupported_media_type, result.status);
    try std.testing.expectEqual(@as(usize, 0), result.upstream_body.len);
    try std.testing.expect(std.mem.indexOf(u8, result.client_body, "Unsupported request body") != null);
}

test "e2e compliance - unsupported response rejected when configured" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const names = [_][]const u8{"Jane Smith"};

    var result = try harness.roundTrip(allocator, "{\"patient\":\"Jane Smith\"}", .{
        .entity_names = &names,
        .upstream_response = "<patient>Entity_A</patient>",
        .upstream_content_type = "application/xml",
        .unsupported_response_body_behavior = body_policy.UnsupportedBodyBehavior.reject,
    });
    defer result.deinit();

    try std.testing.expectEqual(http.Status.bad_gateway, result.status);
    try std.testing.expect(std.mem.indexOf(u8, result.client_body, "unsupported upstream response body") != null);
}

// ---------------------------------------------------------------------------
// NMV2-002 — Request header fidelity (OpenAI, Anthropic, tracing headers)
// ---------------------------------------------------------------------------
test "e2e compliance - request header fidelity" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Hello world";

    const extra_headers = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer sk-test-key-12345" },
        .{ .name = "Accept", .value = "text/event-stream" },
        .{ .name = "OpenAI-Beta", .value = "assistants=v2" },
        .{ .name = "anthropic-version", .value = "2023-06-01" },
        .{ .name = "x-request-id", .value = "trace-abc-123" },
        .{ .name = "User-Agent", .value = "TestClient/1.0" },
    };

    var result = try harness.roundTrip(allocator, body, .{
        .request_extra_headers = &extra_headers,
    });
    defer result.deinit();

    // All end-to-end headers should reach the upstream
    try std.testing.expect(http_util.findHeader(result.upstream_head, "Authorization") != null);
    try std.testing.expect(http_util.findHeader(result.upstream_head, "Accept") != null);
    try std.testing.expect(http_util.findHeader(result.upstream_head, "OpenAI-Beta") != null);
    try std.testing.expect(http_util.findHeader(result.upstream_head, "anthropic-version") != null);
    try std.testing.expect(http_util.findHeader(result.upstream_head, "x-request-id") != null);
    try std.testing.expect(http_util.findHeader(result.upstream_head, "User-Agent") != null);

    // Verify header values are preserved exactly
    const auth_val = http_util.findHeader(result.upstream_head, "Authorization").?;
    try std.testing.expectEqualStrings("Bearer sk-test-key-12345", auth_val);
    const openai_val = http_util.findHeader(result.upstream_head, "OpenAI-Beta").?;
    try std.testing.expectEqualStrings("assistants=v2", openai_val);
    const anthropic_val = http_util.findHeader(result.upstream_head, "anthropic-version").?;
    try std.testing.expectEqualStrings("2023-06-01", anthropic_val);
    const trace_val = http_util.findHeader(result.upstream_head, "x-request-id").?;
    try std.testing.expectEqualStrings("trace-abc-123", trace_val);
    const user_agent_val = http_util.findHeader(result.upstream_head, "User-Agent").?;
    try std.testing.expectEqualStrings("TestClient/1.0", user_agent_val);
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_head, "zig/") == null);
}

// ---------------------------------------------------------------------------
// NMV2-002 — Azure-style vendor headers
// ---------------------------------------------------------------------------
test "e2e compliance - Azure vendor headers" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "{\"prompt\":\"Hello\"}";

    const extra_headers = [_]http.Header{
        .{ .name = "api-key", .value = "azure-key-abcdef" },
        .{ .name = "x-ms-client-request-id", .value = "ms-trace-456" },
    };

    var result = try harness.roundTrip(allocator, body, .{
        .request_extra_headers = &extra_headers,
    });
    defer result.deinit();

    // Azure headers should reach upstream
    const api_key = http_util.findHeader(result.upstream_head, "api-key") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("azure-key-abcdef", api_key);
    const ms_trace = http_util.findHeader(result.upstream_head, "x-ms-client-request-id") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("ms-trace-456", ms_trace);
}

// ---------------------------------------------------------------------------
// NMV2-002 — Internal headers stripped (X-ZPG-Entities must not leak)
// ---------------------------------------------------------------------------
test "e2e compliance - internal headers stripped" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Patient Jane Smith treated today.";
    const names = [_][]const u8{"Jane Smith"};

    const extra_headers = [_]http.Header{
        .{ .name = "Authorization", .value = "Bearer keep-me" },
        .{ .name = "X-ZPG-Entities", .value = "Jane Smith" },
    };

    var result = try harness.roundTrip(allocator, body, .{
        .entity_names = &names,
        .request_extra_headers = &extra_headers,
    });
    defer result.deinit();

    // Authorization should reach upstream
    const auth_val = http_util.findHeader(result.upstream_head, "Authorization") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("Bearer keep-me", auth_val);

    // X-ZPG-Entities is consumed by the proxy and must NOT reach upstream
    try std.testing.expect(http_util.findHeader(result.upstream_head, "X-ZPG-Entities") == null);

    // Entity masking should still work (the header was consumed for redaction)
    try std.testing.expect(std.mem.indexOf(u8, result.upstream_body, "Jane Smith") == null);
}

// ---------------------------------------------------------------------------
// NMV2-002 — Response header fidelity (Set-Cookie, rate-limit, vendor)
// ---------------------------------------------------------------------------
test "e2e compliance - response header fidelity" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    const body = "Hello world";

    const upstream_resp_headers = [_]http.Header{
        .{ .name = "Set-Cookie", .value = "session=abc123; Path=/; HttpOnly" },
        .{ .name = "x-ratelimit-remaining", .value = "42" },
        .{ .name = "x-request-id", .value = "resp-trace-789" },
        .{ .name = "x-custom-vendor", .value = "metadata-value" },
    };

    var result = try harness.roundTrip(allocator, body, .{
        .upstream_extra_headers = &upstream_resp_headers,
    });
    defer result.deinit();

    // All upstream response headers should survive the proxy and reach the client
    const set_cookie = http_util.findHeader(result.client_head, "Set-Cookie") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("session=abc123; Path=/; HttpOnly", set_cookie);

    const rate_limit = http_util.findHeader(result.client_head, "x-ratelimit-remaining") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("42", rate_limit);

    const req_id = http_util.findHeader(result.client_head, "x-request-id") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("resp-trace-789", req_id);

    const vendor = http_util.findHeader(result.client_head, "x-custom-vendor") orelse return error.MissingHeader;
    try std.testing.expectEqualStrings("metadata-value", vendor);
}
