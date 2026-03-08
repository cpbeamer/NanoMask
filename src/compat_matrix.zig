const std = @import("std");
const compatibility_matrix = @import("test/compatibility_matrix.zig");

fn ensureParentPath(output_path: []const u8) !void {
    const parent = std.fs.path.dirname(output_path) orelse return;
    try std.fs.cwd().makePath(parent);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const output_path = if (args.len > 1) args[1] else "compatibility/compatibility-matrix.json";

    const results = try compatibility_matrix.runAll(allocator);
    defer compatibility_matrix.freeResults(allocator, results);

    try ensureParentPath(output_path);
    const file = try std.fs.cwd().createFile(output_path, .{ .truncate = true });
    defer file.close();

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    try compatibility_matrix.writeJson(&out.writer, results);
    try file.writeAll(out.written());

    if (compatibility_matrix.hasUnexpectedRegressions(results)) {
        return error.CompatibilityMatrixFailed;
    }
}
