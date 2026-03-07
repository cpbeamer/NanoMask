const std = @import("std");
pub fn main() void {
    const fields = std.meta.fields(std.Io.Writer);
    inline for (fields) |f| { @compileLog(f.name); }
}
