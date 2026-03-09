const std = @import("std");

fn readFile(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
}

fn expectContainsAll(haystack: []const u8, needles: []const []const u8) !void {
    for (needles) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, haystack, needle) != null);
    }
}

test "integration kits - repo docs link directly to each recipe" {
    const allocator = std.testing.allocator;

    const top_readme = try readFile(allocator, "README.md", 128 * 1024);
    defer allocator.free(top_readme);
    try expectContainsAll(top_readme, &.{
        "examples/integrations/sidecar/README.md",
        "examples/integrations/gateway/README.md",
        "examples/integrations/litellm/README.md",
        "examples/integrations/openai-compatible/README.md",
    });

    const integrations_index = try readFile(allocator, "examples/integrations/README.md", 32 * 1024);
    defer allocator.free(integrations_index);
    try expectContainsAll(integrations_index, &.{
        "sidecar/README.md",
        "gateway/README.md",
        "litellm/README.md",
        "openai-compatible/README.md",
        "../sidecar-pod.yaml",
        "../standalone-deployment.yaml",
    });
}

test "integration kits - sidecar recipe includes localhost wiring and streaming smoke test" {
    const allocator = std.testing.allocator;

    try std.fs.cwd().access("examples/sidecar-pod.yaml", .{});
    try std.fs.cwd().access("examples/integrations/sidecar/docker-compose.yaml", .{});

    const readme = try readFile(allocator, "examples/integrations/sidecar/README.md", 32 * 1024);
    defer allocator.free(readme);
    try expectContainsAll(readme, &.{
        "docker compose -f examples/integrations/sidecar/docker-compose.yaml up -d app nanomask httpbin",
        "curl -N http://127.0.0.1:8081/stream/3",
        "## Auth",
        "## TLS",
        "## Streaming",
        "## Health Checks",
        "examples/sidecar-pod.yaml",
    });

    const compose = try readFile(allocator, "examples/integrations/sidecar/docker-compose.yaml", 16 * 1024);
    defer allocator.free(compose);
    try expectContainsAll(compose, &.{
        "network_mode: \"service:app\"",
        "NANOMASK_LISTEN_HOST: 127.0.0.1",
        "NANOMASK_TARGET_HOST: httpbin",
        "mccutchen/go-httpbin",
        "NANOMASK_AUDIT_LOG: \"true\"",
    });
}

test "integration kits - gateway recipe includes service-backed gateway settings" {
    const allocator = std.testing.allocator;

    try std.fs.cwd().access("examples/standalone-deployment.yaml", .{});
    try std.fs.cwd().access("charts/nanomask/values.yaml", .{});
    try std.fs.cwd().access("examples/integrations/gateway/values.yaml", .{});

    const readme = try readFile(allocator, "examples/integrations/gateway/README.md", 32 * 1024);
    defer allocator.free(readme);
    try expectContainsAll(readme, &.{
        "helm upgrade --install nanomask ./charts/nanomask",
        "examples/integrations/gateway/values.yaml",
        "curl -N http://nanomask.default.svc.cluster.local:8081/stream/3",
        "## Auth",
        "## TLS",
        "## Streaming",
        "## Health Checks",
        "examples/standalone-deployment.yaml",
    });

    const values = try readFile(allocator, "examples/integrations/gateway/values.yaml", 16 * 1024);
    defer allocator.free(values);
    try expectContainsAll(values, &.{
        "listenHost: 0.0.0.0",
        "targetHost: httpbin.org",
        "targetTls: true",
        "enabled: true",
        "path: /metrics",
        "terminationGracePeriodSeconds: 60",
    });
}

test "integration kits - LiteLLM recipe routes through NanoMask with streaming enabled" {
    const allocator = std.testing.allocator;

    try std.fs.cwd().access("examples/integrations/litellm/docker-compose.yaml", .{});
    try std.fs.cwd().access("examples/integrations/litellm/config.yaml", .{});

    const readme = try readFile(allocator, "examples/integrations/litellm/README.md", 32 * 1024);
    defer allocator.free(readme);
    try expectContainsAll(readme, &.{
        "OPENAI_API_KEY",
        "curl -N http://localhost:4000/v1/chat/completions",
        "\"stream\":true",
        "## Auth",
        "## TLS",
        "## Streaming",
        "## Health Checks",
    });

    const compose = try readFile(allocator, "examples/integrations/litellm/docker-compose.yaml", 16 * 1024);
    defer allocator.free(compose);
    try expectContainsAll(compose, &.{
        "ghcr.io/berriai/litellm:main-latest",
        "NANOMASK_TARGET_HOST: api.openai.com",
        "NANOMASK_TARGET_TLS: \"true\"",
        "4000:4000",
        "8081:8081",
    });

    const config = try readFile(allocator, "examples/integrations/litellm/config.yaml", 8 * 1024);
    defer allocator.free(config);
    try expectContainsAll(config, &.{
        "model: openai/gpt-4o-mini",
        "api_base: http://nanomask:8081/v1",
        "api_key: os.environ/OPENAI_API_KEY",
    });
}

test "integration kits - generic OpenAI-compatible clients point at NanoMask" {
    const allocator = std.testing.allocator;

    try std.fs.cwd().access("examples/integrations/openai-compatible/client.env.example", .{});
    try std.fs.cwd().access("examples/integrations/openai-compatible/curl-chat.sh", .{});
    try std.fs.cwd().access("examples/integrations/openai-compatible/python_client.py", .{});
    try std.fs.cwd().access("examples/integrations/openai-compatible/node_client.mjs", .{});

    const readme = try readFile(allocator, "examples/integrations/openai-compatible/README.md", 32 * 1024);
    defer allocator.free(readme);
    try expectContainsAll(readme, &.{
        "OPENAI_BASE_URL=http://127.0.0.1:8081/v1",
        "curl-chat.sh",
        "python_client.py",
        "node_client.mjs",
        "## Auth",
        "## TLS",
        "## Streaming",
        "## Health Checks",
    });

    const env_example = try readFile(allocator, "examples/integrations/openai-compatible/client.env.example", 4 * 1024);
    defer allocator.free(env_example);
    try expectContainsAll(env_example, &.{
        "OPENAI_BASE_URL=http://127.0.0.1:8081/v1",
        "OPENAI_MODEL=gpt-4o-mini",
    });

    const curl_script = try readFile(allocator, "examples/integrations/openai-compatible/curl-chat.sh", 8 * 1024);
    defer allocator.free(curl_script);
    try expectContainsAll(curl_script, &.{
        "curl -N",
        "/chat/completions",
        "\\\"stream\\\":true",
    });

    const python_client = try readFile(allocator, "examples/integrations/openai-compatible/python_client.py", 8 * 1024);
    defer allocator.free(python_client);
    try expectContainsAll(python_client, &.{
        "base_url=os.environ.get(\"OPENAI_BASE_URL\", \"http://127.0.0.1:8081/v1\")",
        "stream=True",
    });

    const node_client = try readFile(allocator, "examples/integrations/openai-compatible/node_client.mjs", 8 * 1024);
    defer allocator.free(node_client);
    try expectContainsAll(node_client, &.{
        "baseURL: process.env.OPENAI_BASE_URL ?? \"http://127.0.0.1:8081/v1\"",
        "stream: true",
    });
}
