// sbcache.zig — compile the Seatbelt profile once per run. sandbox_init
// compiles the profile text on every call, about 2 ms of a stub's start, and
// every exec in a forked process starts a fresh stub. The first stub compiles
// the profile with sandbox_compile_string, saves the bytecode next to the
// channel file, and applies it with sandbox_apply; later stubs apply the saved
// bytecode directly (the same private libsandbox entry points Chromium uses).
// Without those it falls back to sandbox_init_with_parameters.
//
// The profile's TMP parameter comes from <chan>.paths, written by the
// supervisor before it starts any stub: one NUL-terminated host path.

const std = @import("std");

const Profile = extern struct {
    builtin: ?[*:0]const u8,
    data: ?[*]const u8,
    size: usize,
};

const RTLD_NOW: c_int = 2;
extern "c" fn dlopen(path: [*:0]const u8, mode: c_int) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
extern "c" fn sandbox_init_with_parameters(profile: [*:0]const u8, flags: u64, params: [*:null]const ?[*:0]const u8, errorbuf: *?[*:0]u8) c_int;

const ApplyFn = *const fn (*const Profile) callconv(.C) c_int;
const CompileFn = *const fn ([*:0]const u8, ?*anyopaque, *?[*:0]u8) callconv(.C) ?*Profile;
const FreeFn = *const fn (*Profile) callconv(.C) void;
const ParamsFn = *const fn () callconv(.C) ?*anyopaque;
const SetParamFn = *const fn (?*anyopaque, [*:0]const u8, [*:0]const u8) callconv(.C) c_int;

fn sym(comptime T: type, lib: ?*anyopaque, name: [*:0]const u8) ?T {
    return @ptrCast(@alignCast(dlsym(lib orelse return null, name) orelse return null));
}

// apply sandboxes this process with profile, using the bytecode cached at
// <chan_path>.sb when present. It returns false if nothing was applied.
pub fn apply(profile: [*:0]const u8, chan_path: [*:0]const u8) bool {
    const lib = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW);
    const apply_fn = sym(ApplyFn, lib, "sandbox_apply");
    var pbuf: [1024]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pbuf, "{s}.sb", .{std.mem.span(chan_path)}) catch return false;
    const alloc = std.heap.page_allocator;
    if (apply_fn) |f| {
        if (std.fs.cwd().readFileAlloc(alloc, path, 1 << 22)) |data| {
            const p = Profile{ .builtin = null, .data = data.ptr, .size = data.len };
            return f(&p) == 0;
        } else |_| {}
    }

    var qbuf: [1024]u8 = undefined;
    const qpath = std.fmt.bufPrint(&qbuf, "{s}.paths", .{std.mem.span(chan_path)}) catch return false;
    const raw = std.fs.cwd().readFileAlloc(alloc, qpath, 1 << 16) catch return false;
    if (raw.len < 2 or std.mem.indexOfScalar(u8, raw, 0) != raw.len - 1) return false;
    const tmp: [*:0]const u8 = @ptrCast(raw.ptr);

    var err: ?[*:0]u8 = null;
    compiled: {
        const f = apply_fn orelse break :compiled;
        const compile_fn = sym(CompileFn, lib, "sandbox_compile_string") orelse break :compiled;
        const params_fn = sym(ParamsFn, lib, "sandbox_create_params") orelse break :compiled;
        const set_fn = sym(SetParamFn, lib, "sandbox_set_param") orelse break :compiled;
        const free_fn = sym(FreeFn, lib, "sandbox_free_profile") orelse break :compiled;
        const params = params_fn() orelse break :compiled;
        if (set_fn(params, "TMP", tmp) != 0) return false;
        const p = compile_fn(profile, params, &err) orelse return false;
        defer free_fn(p);
        if (p.data) |d| save(path, d[0..p.size]);
        return f(p) == 0;
    }
    const kv = [_:null]?[*:0]const u8{ "TMP", tmp };
    return sandbox_init_with_parameters(profile, 0, &kv, &err) == 0;
}

// save writes the bytecode atomically (temp file + rename), so a stub never
// reads a partial profile.
fn save(path: [:0]const u8, data: []const u8) void {
    var tbuf: [1040]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tbuf, "{s}.tmp", .{path}) catch return;
    const f = std.fs.cwd().createFile(tmp, .{ .exclusive = true }) catch return;
    f.writeAll(data) catch {
        f.close();
        std.fs.cwd().deleteFile(tmp) catch {};
        return;
    };
    f.close();
    std.fs.cwd().rename(tmp, path) catch {};
}
