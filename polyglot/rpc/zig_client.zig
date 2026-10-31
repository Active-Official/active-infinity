// Thin Active RPC client over native ARP1 on TCP (Zig, libc sockets).
//
//   zig build-exe polyglot/rpc/zig_client.zig -femit-bin=/tmp/rpc-client-zig -lc

const std = @import("std");
const c = @cImport({
    @cInclude("arpa/inet.h");
    @cInclude("netinet/in.h");
    @cInclude("stdio.h");
    @cInclude("stdlib.h");
    @cInclude("string.h");
    @cInclude("sys/socket.h");
    @cInclude("unistd.h");
});

const budget = [_]u64{ 10000, 64 << 20, 5000, 100000, 256, 100000, 10000000 };

fn putU32(out: []u8, cursor: *usize, value: u32) void {
    std.mem.writeInt(u32, out[cursor.*..][0..4], value, .little);
    cursor.* += 4;
}

fn putU64(out: []u8, cursor: *usize, value: u64) void {
    std.mem.writeInt(u64, out[cursor.*..][0..8], value, .little);
    cursor.* += 8;
}

fn putString(out: []u8, cursor: *usize, text: []const u8) void {
    putU32(out, cursor, @intCast(text.len));
    @memcpy(out[cursor.*..][0..text.len], text);
    cursor.* += text.len;
}

fn request(out: []u8, id: u64, method: []const u8, payload: []const u8, cap: ?[16]u8) usize {
    var cursor: usize = 0;
    @memcpy(out[0..4], "ARP1");
    cursor = 4;
    out[cursor] = 1;
    cursor += 1;
    out[cursor] = 1;
    cursor += 1;
    out[cursor] = 0;
    cursor += 1;
    out[cursor] = 0;
    cursor += 1;
    putU64(out, &cursor, id);
    putString(out, &cursor, method);
    putU32(out, &cursor, 0);
    putU32(out, &cursor, @intCast(payload.len));
    @memcpy(out[cursor..][0..payload.len], payload);
    cursor += payload.len;
    if (cap) |id_bytes| {
        putU32(out, &cursor, 1);
        @memcpy(out[cursor..][0..16], &id_bytes);
        cursor += 16;
        putU32(out, &cursor, 1);
        putString(out, &cursor, "echo");
        for (budget) |value| putU64(out, &cursor, value);
        out[cursor] = 0;
        cursor += 1;
        out[cursor] = 0;
        cursor += 1;
        out[cursor] = 0;
        cursor += 1;
    } else {
        putU32(out, &cursor, 0);
    }
    return cursor;
}

fn readFile(allocator: std.mem.Allocator, path: [:0]const u8) ![]u8 {
    const file = c.fopen(path.ptr, "rb") orelse return error.OpenFailed;
    defer _ = c.fclose(file);
    _ = c.fseek(file, 0, c.SEEK_END);
    const length = c.ftell(file);
    if (length < 0) return error.SizeFailed;
    _ = c.rewind(file);
    const buffer = try allocator.alloc(u8, @intCast(length));
    if (c.fread(buffer.ptr, 1, buffer.len, file) != buffer.len) return error.ReadFailed;
    return buffer;
}

fn writeAll(fd: c_int, data: []const u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const sent = c.send(fd, data[offset..].ptr, data.len - offset, 0);
        if (sent <= 0) return error.SendFailed;
        offset += @intCast(sent);
    }
}

fn readAll(fd: c_int, data: []u8) !void {
    var offset: usize = 0;
    while (offset < data.len) {
        const received = c.recv(fd, data[offset..].ptr, data.len - offset, 0);
        if (received <= 0) return error.RecvFailed;
        offset += @intCast(received);
    }
}

fn getU32(data: []const u8) u32 {
    return std.mem.readInt(u32, data[0..4], .little);
}

fn call(allocator: std.mem.Allocator, address: []const u8, envelope: []const u8) ![]u8 {
    const colon = std.mem.lastIndexOfScalar(u8, address, ':') orelse return error.BadAddress;
    const port = try std.fmt.parseInt(u16, address[colon + 1 ..], 10);
    var host_buffer: [128]u8 = undefined;
    @memcpy(host_buffer[0..colon], address[0..colon]);
    host_buffer[colon] = 0;

    const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    defer _ = c.close(fd);
    var target: c.struct_sockaddr_in = std.mem.zeroes(c.struct_sockaddr_in);
    target.sin_family = c.AF_INET;
    target.sin_port = c.htons(port);
    if (c.inet_pton(c.AF_INET, &host_buffer, &target.sin_addr) != 1) return error.BadHost;
    if (c.connect(fd, @ptrCast(&target), @sizeOf(c.struct_sockaddr_in)) != 0) return error.ConnectFailed;

    var header: [4]u8 = undefined;
    std.mem.writeInt(u32, &header, @intCast(envelope.len), .little);
    try writeAll(fd, &header);
    try writeAll(fd, envelope);
    try readAll(fd, &header);
    const length = getU32(&header);
    if (length < 20 or length > 1 << 20) return error.BadFrame;
    const body = try allocator.alloc(u8, length);
    errdefer allocator.free(body);
    try readAll(fd, body);
    if (!std.mem.eql(u8, body[0..4], "ARP1") or body[4] != 1) return error.BadMagic;
    return body;
}

fn echoes(body: []const u8, payload: []const u8) bool {
    if (body.len < payload.len + 8) return false;
    if (getU32(body[body.len - 4 ..]) != 0) return false;
    return std.mem.eql(u8, body[body.len - 4 - payload.len .. body.len - 4], payload);
}

fn errorMethodIs(body: []const u8, expected: []const u8) bool {
    if (body.len < 20) return false;
    const method_length = getU32(body[16..20]);
    if (20 + method_length > body.len) return false;
    return std.mem.eql(u8, body[20 .. 20 + method_length], expected);
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const address = std.mem.span(c.getenv("ACTIVE_RPC_ADDR") orelse return error.MissingAddress);
    const cap_hex = std.mem.span(c.getenv("ACTIVE_RPC_CAP") orelse return error.MissingCap);
    const payload_path = std.mem.span(c.getenv("ACTIVE_RPC_PAYLOAD") orelse return error.MissingPayload);
    if (cap_hex.len != 32) return error.BadCap;
    var cap: [16]u8 = undefined;
    _ = try std.fmt.hexToBytes(&cap, cap_hex);
    const payload = try readFile(allocator, payload_path);

    var buffer: [1 << 20]u8 = undefined;

    var length = request(&buffer, 42, "echo", payload, cap);
    var body = try call(allocator, address, buffer[0..length]);
    if (body[5] != 2 or std.mem.readInt(u64, body[8..16], .little) != 42 or !echoes(body, payload)) {
        return error.EchoFailed;
    }

    length = request(&buffer, 43, "refuse", payload, cap);
    body = try call(allocator, address, buffer[0..length]);
    if (body[5] != 3 or !errorMethodIs(body, "rpc/method-not-granted")) return error.RefusalFailed;

    length = request(&buffer, 44, "echo", payload, null);
    body = try call(allocator, address, buffer[0..length]);
    if (body[5] != 3 or !errorMethodIs(body, "rpc/unknown-capability")) return error.CapabilityFailed;

    std.debug.print("Zig thin RPC PASS (echo, refusal, missing capability)\n", .{});
}
