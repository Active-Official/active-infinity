//! Active Infinity for Zig: validate, content hash, canonical re-encode and
//! redacted JSON through the C ABI.
//!
//! Build from this directory (after the reference library exists):
//!   zig build
//!   zig build run -- ../../tests/vectors/valid/full.ainf
//!   zig build run -- ../../tests/vectors/valid/full.ainf <content_hash>
//!   zig build run -- ../../tests/vectors/invalid/bad_magic.ainf --expect-code infinity/magic
//!
//! INF-POLY-02: the consumer used to print the content hash without
//! comparing it to the manifest, and it never ran on a hostile vector, so
//! a wrong hash or a wrong refusal code passed silently. The optional
//! expected-hash argument and the --expect-code hostile mode close both
//! gaps; CI passes the manifest hash for full.ainf and loops the invalid
//! vectors through this binary.
//!
//! INF-FFI-02: the --limits flag narrows one ceiling (e.g. --limits
//! max_nodes:1) and routes the hostile mode through validate_with_limits,
//! so the two limits-dependent vectors (limit, too_deep) are checked here
//! instead of being skipped.

const std = @import("std");
const c = @cImport({
    @cInclude("stdio.h");
    @cInclude("active_infinity.h");
});

fn fail(what: []const u8, status: i32) noreturn {
    const pointer = c.active_infinity_last_error();
    const code = if (pointer == null) "infinity/unknown" else std.mem.span(pointer);
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
        std.debug.print("usage: active-infinity-zig <image.ainf> [expected-hash-hex] [--expect-code <code>]\n", .{});
        std.process.exit(2);
    };
    var expected_hash: ?[]const u8 = null;
    var expected_code: ?[]const u8 = null;
    var limits_spec: ?[]const u8 = null;
    while (arguments.next()) |argument| {
        if (std.mem.eql(u8, argument, "--expect-code")) {
            expected_code = arguments.next() orelse {
                std.debug.print("--expect-code needs a code\n", .{});
                std.process.exit(2);
            };
        } else if (std.mem.eql(u8, argument, "--limits")) {
            limits_spec = arguments.next() orelse {
                std.debug.print("--limits needs a field:value spec\n", .{});
                std.process.exit(2);
            };
        } else if (expected_hash == null) {
            expected_hash = argument;
        } else {
            std.debug.print("unexpected argument: {s}\n", .{argument});
            std.process.exit(2);
        }
    }

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

    // INF-POLY-02: hostile mode -- the image must be refused by
    // validate_canonical with exactly the expected code. INF-FFI-02: with
    // --limits, the refusal goes through validate_with_limits under the
    // narrowed budget instead.
    if (expected_code) |code| {
        const status = if (limits_spec) |spec| blk: {
            var limits: c.active_infinity_limits = undefined;
            if (c.active_infinity_limits_default(&limits) != 0) {
                std.debug.print("FAIL limits default failed\n", .{});
                std.process.exit(2);
            }
            const colon = std.mem.indexOfScalar(u8, spec, ':') orelse {
                std.debug.print("FAIL bad --limits spec: {s}\n", .{spec});
                std.process.exit(2);
            };
            const field = spec[0..colon];
            const value = std.fmt.parseUnsigned(u64, spec[colon + 1 ..], 10) catch {
                std.debug.print("FAIL bad --limits spec: {s}\n", .{spec});
                std.process.exit(2);
            };
            // One branch per ceiling, in C struct order; an unknown field
            // fails closed.
            if (std.mem.eql(u8, field, "max_nodes")) {
                limits.max_nodes = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_edges")) {
                limits.max_edges = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_children")) {
                limits.max_children = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_fields")) {
                limits.max_fields = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_parts")) {
                limits.max_parts = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_strings")) {
                limits.max_strings = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_string_bytes")) {
                limits.max_string_bytes = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_blobs")) {
                limits.max_blobs = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_blob_bytes")) {
                limits.max_blob_bytes = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_annotations")) {
                limits.max_annotations = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_units")) {
                limits.max_units = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_types")) {
                limits.max_types = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_aux")) {
                limits.max_aux = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_numbers")) {
                limits.max_numbers = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_secrets")) {
                limits.max_secrets = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_secret_bytes")) {
                limits.max_secret_bytes = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_extensions")) {
                limits.max_extensions = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_prov_bytes")) {
                limits.max_prov_bytes = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_prov_entries")) {
                limits.max_prov_entries = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_hashes")) {
                limits.max_hashes = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_bindings")) {
                limits.max_bindings = @intCast(value);
            } else if (std.mem.eql(u8, field, "max_total_bytes")) {
                limits.max_total_bytes = value;
            } else if (std.mem.eql(u8, field, "max_decoded_bytes")) {
                limits.max_decoded_bytes = value;
            } else if (std.mem.eql(u8, field, "max_depth")) {
                limits.max_depth = @intCast(value);
            } else {
                std.debug.print("FAIL unknown limits field: {s}\n", .{field});
                std.process.exit(2);
            }
            break :blk c.active_infinity_validate_with_limits(image.ptr, image.len, &limits);
        } else c.active_infinity_validate_canonical(image.ptr, image.len);
        if (status == c.ACTIVE_INFINITY_OK) {
            std.debug.print("FAIL invalid image was accepted\n", .{});
            std.process.exit(1);
        }
        const pointer = c.active_infinity_last_error();
        const actual = if (pointer == null) "infinity/unknown" else std.mem.span(pointer);
        if (!std.mem.eql(u8, actual, code)) {
            std.debug.print("FAIL wrong code: {s}, want {s}\n", .{ actual, code });
            std.process.exit(1);
        }
        std.debug.print("PASS (refused with {s})\n", .{code});
        return;
    }

    check(c.active_infinity_validate(image.ptr, image.len), "validate");
    // INF-POLY-03: `validate` already proves the canonical form (INF-02);
    // this states the requirement explicitly.
    check(c.active_infinity_validate_canonical(image.ptr, image.len), "validate canonical");

    var hash: [32]u8 = undefined;
    check(c.active_infinity_content_hash(image.ptr, image.len, &hash), "content hash");
    const hex = std.fmt.bytesToHex(hash, .lower);
    std.debug.print("hash={s}\n", .{hex});
    // INF-POLY-02: the consumer used to print the hash without comparing
    // it to the manifest, so a wrong hash passed silently.
    if (expected_hash) |want| {
        if (!std.mem.eql(u8, &hex, want)) {
            std.debug.print("FAIL hash mismatch: {s}, want {s}\n", .{ hex, want });
            std.process.exit(1);
        }
    }

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
