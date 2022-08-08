const std = @import("std");
const math = std.math;
const testing = std.testing;

fn ipv4ToDecimal(ipv4: []const u8) u32 {
    var shift: u8 = 0;
    var digit: u8 = 0;
    var octet: u32 = 0;
    var sum: u32 = 0;
    for (ipv4) |char| {
        if (char == 46) {
            var real_shift = 8 * (3 - shift);
            sum += @shlExact(octet, @intCast(u5, real_shift));
            shift += 1;
            digit = 0;
            octet = 0;
            continue;
        }
        if (digit > 0) {
            octet *= 10;
        }
        octet += (char - 48);
        digit += 1;
    }
    return sum + octet;
}

fn decimalToIpv4(decimal: u32) [4]u8 {
    return [4]u8{ getSection(decimal, 24), getSection(decimal, 16), getSection(decimal, 8), getSection(decimal, 0) };
}

fn getSection(decimal: u32, mask: u5) u8 {
    return @truncate(u8, decimal >> mask) & 255;
}

fn createNetMask(comptime T: type, max: T, size: T) T {
    return math.pow(T, 2, max) - math.pow(T, 2, 32 - size);
}

pub fn cidrToIpv4Range(cidr: []const u8) [2][4]u8 {
    var split_it = std.mem.split(u8, cidr, "/");
    const ipaddress = split_it.next().?;
    const netmask = ipv4ToDecimal(split_it.next() orelse "32");
    const startDecimal = ipv4ToDecimal(ipaddress) & @truncate(u32, createNetMask(u33, 32, netmask));
    const endDecimal = math.pow(u32, 2, 32 - netmask) + startDecimal - 1;
    return [2][4]u8{ decimalToIpv4(startDecimal), decimalToIpv4(endDecimal) };
}

pub fn ipv4RangeToCidr(allocator: std.mem.Allocator, range: [2][]const u8) ![][5]u8 {
    var start = ipv4ToDecimal(range[0]);
    const end = ipv4ToDecimal(range[1]);
    var cidr = std.ArrayList([5]u8).init(allocator);
    while (end >= start) {
        var maxSize: u8 = 32;
        while (maxSize > 0) {
            const mask = @truncate(u32, createNetMask(u33, 32, maxSize - 1));
            if ((start & mask) != start) {
                break;
            }
            maxSize -= 1;
        }
        const diff: u8 = 32 - @truncate(u8, @floatToInt(u8, math.log2(@intToFloat(f32, end - start + 1))));
        if (maxSize < diff) {
            maxSize = diff;
        }
        var dest: [5]u8 = undefined;
        const ipv4 = decimalToIpv4(start);
        for (ipv4[0..]) |b, i| dest[i] = b;
        dest[4] = maxSize;
        try cidr.append(dest);
        start += @truncate(u32, math.pow(u33, 2, 32 - maxSize));
    }

    return cidr.items;
}

// Only for testing
fn assertIpv4(actual: [4]u8, expected: [4]u8) !void {
    try testing.expect(actual[0] == expected[0]);
    try testing.expect(actual[1] == expected[1]);
    try testing.expect(actual[2] == expected[2]);
    try testing.expect(actual[3] == expected[3]);
}

fn assertCidr(actual: [5]u8, expected: [5]u8) !void {
    try testing.expect(actual[0] == expected[0]);
    try testing.expect(actual[1] == expected[1]);
    try testing.expect(actual[2] == expected[2]);
    try testing.expect(actual[3] == expected[3]);
    try testing.expect(actual[4] == expected[4]);
}

test "IPv4 to Decimal" {
    try testing.expect(ipv4ToDecimal("192.168.0.1") == 3232235521);
}

test "Decimal to IPv4" {
    var ipv4 = decimalToIpv4(3232235521);
    try assertIpv4(ipv4, [4]u8{ 192, 168, 0, 1 });
}

test "Cidr to IPv4 range" {
    var range = cidrToIpv4Range("192.168.0.1/24");
    try testing.expect(range.len == 2);
    try assertIpv4(range[0], [4]u8{ 192, 168, 0, 0 });
    try assertIpv4(range[1], [4]u8{ 192, 168, 0, 255 });
}

test "IPv4 range to cidr" {
    var allocator = testing.allocator;
    var cidr = try ipv4RangeToCidr(allocator, [2][]const u8{ "192.168.0.1", "192.168.0.10" });
    defer allocator.free(cidr);
    try testing.expect(cidr.len == 5);

    try assertCidr(cidr[0], [5]u8{ 192, 168, 0, 1, 32 });
    try assertCidr(cidr[1], [5]u8{ 192, 168, 0, 2, 31 });
    try assertCidr(cidr[2], [5]u8{ 192, 168, 0, 4, 30 });
    try assertCidr(cidr[3], [5]u8{ 192, 168, 0, 8, 31 });
    try assertCidr(cidr[4], [5]u8{ 192, 168, 0, 10, 32 });
}
