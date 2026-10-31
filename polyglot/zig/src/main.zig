//! Active Infinity for Zig: validate, content hash, canonical re-encode and
//! redacted JSON through the C ABI.
//!
//! Build from this directory (after the reference library exists):
//!   zig build
//!   zig build run -- ../../tests/vectors/valid/full.ainf

const std = @import("std");
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("active_infinity.h");
});

fn fail(what: []const u8, status: i32) noreturn {
    const code = std.mem.span(c.active_infinity_last_error());
    std.debug.print("FAIL {s}: {s} ({d})\n", .{ what, code, status });
    std.process.exit(1);
}

fn check(status: i32, what: []const u8) void {
    if (status != c.ACTIVE_INFINITY_OK) fail(what, status);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var arguments = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer arguments.deinit();
    _ = arguments.next(); // program name
    const image_path = arguments.next() orelse {
        std.debug.print("usage: active-infinity-zig <image.ainf>\n", .{});
        std.process.exit(2);
    };

    if (c.active_infinity_abi_version() != c.ACTIVE_INFINITY_ABI_VERSION) {
        std.debug.print("ABI mismatch\n", .{});
        std.process.exit(2);
    }

    const file = c.fopen(image_path.ptr, "rb") orelse {
        std.debug.print("cannot open {s}\n", .{image_path});
        std.process.exit(2);
    };
    defer _ = c.fclose(file);
    if (c.fseek(file, 0, c.SEEK_END) != 0) std.process.exit(2);
    const length = c.ftell(file);
    if (length < 0) std.process.exit(2);
    _ = c.rewind(file);
    const image = try allocator.alloc(u8, @intCast(length));
    defer allocator.free(image);
    if (c.fread(image.ptr, 1, image.len, file) != image.len) std.process.exit(2);

    check(c.active_infinity_validate(image.ptr, image.len), "validate");

    var hash: [32]u8 = undefined;
    check(c.active_infinity_content_hash(image.ptr, image.len, &hash), "content hash");
    std.debug.print("hash={s}\n", .{std.fmt.bytesToHex(hash, .lower)});

    var size: usize = 0;
    const probe = c.active_infinity_reencode(image.ptr, image.len, null, &size);
    if (probe != c.ACTIVE_INFINITY_BUFFER_TOO_SMALL or size == 0) fail("size query", probe);
    const canonical = try allocator.alloc(u8, size);
    defer allocator.free(canonical);
    var capacity = size;
    check(c.active_infinity_reencode(image.ptr, image.len, canonical.ptr, &capacity), "reencode");
    if (capacity != image.len or !std.mem.eql(u8, canonical[0..capacity], image)) {
        std.debug.print("FAIL canonical bytes differ\n", .{});
        std.process.exit(1);
    }

    var json_size: usize = 0;
    const json_probe = c.active_infinity_redacted_json(image.ptr, image.len, null, &json_size);
    if (json_probe != c.ACTIVE_INFINITY_BUFFER_TOO_SMALL or json_size == 0) fail("json size", json_probe);
    const json = try allocator.alloc(u8, json_size);
    defer allocator.free(json);
    var json_capacity = json_size;
    check(c.active_infinity_redacted_json(image.ptr, image.len, json.ptr, &json_capacity), "json");
    if (std.mem.indexOf(u8, json[0..json_capacity], "CANARY_SECRET_") != null) {
        std.debug.print("FAIL redaction canary survived\n", .{});
        std.process.exit(1);
    }

    std.debug.print("PASS\n", .{});
}
