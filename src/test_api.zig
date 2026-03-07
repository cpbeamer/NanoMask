const std = @import("std");
pub fn main() void {
    @compileLog(@TypeOf(std.http.Server));
    @compileLog(@TypeOf(std.http.Client));
}
