const std = @import("std");
const proof_harness = @import("proof/harness.zig");

fn ensureParentPath(output_path: []const u8) !void {
    const parent = std.fs.path.dirname(output_path) orelse return;
    try std.fs.cwd().makePath(parent);
}

fn writeFile(path: []const u8, bytes: []const u8) !void {
    try ensureParentPath(path);
    const file = try std.fs.cwd().createFile(path, .{ .truncate = true });
    defer file.close();
    try file.writeAll(bytes);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const json_path = if (args.len > 1) args[1] else "zig-out/proof/proof-report.json";
    const markdown_path = if (args.len > 2) args[2] else "zig-out/proof/proof-report.md";

    const report = try proof_harness.runReport(allocator);

    var json_out: std.Io.Writer.Allocating = .init(allocator);
    defer json_out.deinit();
    try proof_harness.writeJson(&json_out.writer, report);
    try writeFile(json_path, json_out.written());

    var markdown_out: std.Io.Writer.Allocating = .init(allocator);
    defer markdown_out.deinit();
    try proof_harness.writeMarkdown(&markdown_out.writer, report);
    try writeFile(markdown_path, markdown_out.written());

    if (proof_harness.hasHardFailures(report)) {
        return error.ProofHarnessFailed;
    }
}
