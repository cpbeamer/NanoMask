const std = @import("std");
const compatibility_matrix = @import("test/compatibility_matrix.zig");

fn ensureParentPath(output_path: []const u8) !void {
    const parent = std.fs.path.dirname(output_path) orelse return;
    try std.fs.cwd().makePath(parent);
}

/// Replace the file extension of a path, or append the new extension if none exists.
fn replaceExtension(allocator: std.mem.Allocator, path: []const u8, new_ext: []const u8) ![]u8 {
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse path.len;
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ path[0..dot], new_ext });
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const json_path = if (args.len > 1) args[1] else "compatibility/compatibility-matrix.json";
    const md_path_owned = if (args.len > 2) null else try replaceExtension(allocator, json_path, ".md");
    defer if (md_path_owned) |p| allocator.free(p);
    const md_path = if (args.len > 2) args[2] else md_path_owned.?;

    const results = try compatibility_matrix.runAll(allocator);
    defer compatibility_matrix.freeResults(allocator, results);

    // Write JSON artifact
    try ensureParentPath(json_path);
    {
        const file = try std.fs.cwd().createFile(json_path, .{ .truncate = true });
        defer file.close();

        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        try compatibility_matrix.writeJson(&out.writer, results);
        try file.writeAll(out.written());
    }

    // Write Markdown summary
    try ensureParentPath(md_path);
    {
        const file = try std.fs.cwd().createFile(md_path, .{ .truncate = true });
        defer file.close();

        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();
        try compatibility_matrix.writeMarkdown(&out.writer, results);
        try file.writeAll(out.written());
    }

    if (compatibility_matrix.hasUnexpectedRegressions(results)) {
        return error.CompatibilityMatrixFailed;
    }
}
