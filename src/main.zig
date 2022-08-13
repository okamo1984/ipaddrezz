const std = @import("std");
const math = std.math;
const fmt = std.fmt;
const testing = std.testing;

const IPAddressTag = enum {
    v4,
    v6,
};

const IPAddress = union(IPAddressTag) {
    v4: [4]u8,
    v6: [8][4]u8,

    const Self = @This();

    pub fn print(self: Self, writer: anytype) !void {
        switch (self) {
            .v4 => {
                const v4 = self.v4;
                try fmt.format(writer, "{d}.{d}.{d}.{d}", .{ v4[0], v4[1], v4[2], v4[3] });
            },
            .v6 => {
                const v6 = self.v6;
                try fmt.format(writer, "{s}:{s}:{s}:{s}:{s}:{s}:{s}:{s}", .{ v6[0], v6[1], v6[2], v6[3], v6[4], v6[5], v6[6], v6[7] });
            },
        }
    }

    pub fn isV4(self: Self) bool {
        return self == IPAddressTag.v4;
    }

    pub fn isV6(self: Self) bool {
        return self == IPAddressTag.v6;
    }
};

fn stringToUint8(s: []const u8) u8 {
    var sum: u8 = 0;
    for (s) |char| {
        if (sum > 0) {
            sum *= 10;
        }
        sum += (char - 48);
    }
    return sum;
}

fn ipv4ToDecimal(ipv4: []const u8) u32 {
    var shift: u8 = 0;
    var octet: u32 = 0;
    var sum: u32 = 0;
    for (ipv4) |char| {
        if (char == 46) {
            var real_shift = 8 * (3 - shift);
            sum += @shlExact(octet, @intCast(u5, real_shift));
            shift += 1;
            octet = 0;
            continue;
        }
        if (octet > 0) {
            octet *= 10;
        }
        octet += (char - 48);
    }
    return sum + octet;
}

fn decimalToIpv4(decimal: u32) IPAddress {
    return .{ .v4 = .{ getIpv4Section(decimal, 24), getIpv4Section(decimal, 16), getIpv4Section(decimal, 8), getIpv4Section(decimal, 0) } };
}

fn getIpv4Section(decimal: u32, mask: u5) u8 {
    return @truncate(u8, decimal >> mask) & 255;
}

fn createNetMask(comptime T: type, max: T, size: T) T {
    return math.pow(T, 2, max) - math.pow(T, 2, max - size);
}

pub const IPAddressRange = struct {
    start: IPAddress,
    end: IPAddress,

    const Self = @This();

    pub fn init(start: IPAddress, end: IPAddress) IPAddressRange {
        return IPAddressRange{
            .start = start,
            .end = end,
        };
    }

    pub fn print(self: Self, writer: anytype) !void {
        if (self.isValidRange()) {
            try fmt.format(writer, "start: ", .{});
            try self.start.print(writer);
            try fmt.format(writer, "\n", .{});
            try fmt.format(writer, "end: ", .{});
            try self.end.print(writer);
            try fmt.format(writer, "\n", .{});
        }
    }

    fn isValidRange(self: Self) bool {
        return (self.start.isV4() and self.end.isV4()) or (self.start.isV6() and self.end.isV6());
    }
};

pub fn cidrToIpv4Range(cidr: []const u8) IPAddressRange {
    var split_it = std.mem.split(u8, cidr, "/");
    const ipaddress = split_it.next().?;
    const netmask = stringToUint8(split_it.next() orelse "32");
    const startDecimal = ipv4ToDecimal(ipaddress) & @truncate(u32, createNetMask(u33, 32, netmask));
    const endDecimal = math.pow(u32, 2, 32 - netmask) + startDecimal - 1;
    return IPAddressRange.init(decimalToIpv4(startDecimal), decimalToIpv4(endDecimal));
}

pub const Cidr = struct {
    address: IPAddress,
    netmask: u8,

    const Self = @This();

    pub fn init(address: IPAddress, netmask: u8) Cidr {
        return Cidr{ .address = address, .netmask = netmask };
    }

    pub fn print(self: Self, writer: anytype) !void {
        try self.address.print(writer);
        try fmt.format(writer, "/{d}", .{self.netmask});
    }
};

pub fn ipv4RangeToCidr(allocator: std.mem.Allocator, range: [2][]const u8) ![]Cidr {
    var start = ipv4ToDecimal(range[0]);
    const end = ipv4ToDecimal(range[1]);
    var cidr = std.ArrayList(Cidr).init(allocator);
    while (end >= start) {
        var maxSize: u8 = 32;
        while (maxSize > 0) {
            const mask = @truncate(u32, createNetMask(u33, 32, maxSize - 1));
            if ((start & mask) != start) {
                break;
            }
            maxSize -= 1;
        }
        const diff: u8 = 32 - @floatToInt(u8, math.log2(@intToFloat(f32, end - start + 1)));
        if (maxSize < diff) {
            maxSize = diff;
        }
        try cidr.append(Cidr.init(decimalToIpv4(start), maxSize));
        start += @truncate(u32, math.pow(u33, 2, 32 - maxSize));
    }

    return cidr.items;
}

fn ipv6ToDecimal(ipv6: []const u8) u128 {
    var shift: u8 = 0;
    var hextet: u16 = 0;
    var sum: u128 = 0;
    for (ipv6) |char| {
        if (char == 58) {
            sum += (hextet * math.pow(u128, 2, 16 * (7 - shift)));
            shift += 1;
            hextet = 0;
            continue;
        }
        if (hextet > 0) {
            hextet *= 16;
        }
        hextet += getHex(char);
    }
    return sum + hextet;
}

fn getHex(char: u8) u8 {
    return switch (char) {
        48...57 => char - 48,
        65...70 => char - 55,
        97...102 => char - 87,
        else => unreachable,
    };
}

fn decimalToIpv6(decimal: u128) IPAddress {
    return .{ .v6 = .{ getIpv6Section(decimal, 112), getIpv6Section(decimal, 96), getIpv6Section(decimal, 80), getIpv6Section(decimal, 64), getIpv6Section(decimal, 48), getIpv6Section(decimal, 32), getIpv6Section(decimal, 16), getIpv6Section(decimal, 0) } };
}

fn getIpv6Section(decimal: u128, mask: u7) [4]u8 {
    return hexToIpv6Section(@truncate(u16, decimal >> mask) & @truncate(u16, math.pow(u17, 2, 16) - 1));
}

fn hexToIpv6Section(hex: u16) [4]u8 {
    var section: [4]u8 = .{ '0', '0', '0', '0' };
    var temp: u16 = hex;
    var digit: u3 = 0;
    while (temp / 16 > 0) {
        section[3 - digit] = decimalToChar(@intCast(u8, temp % 16));
        temp /= 16;
        digit += 1;
    }
    section[3 - digit] = decimalToChar(@intCast(u8, temp));
    return section;
}

fn decimalToChar(decimal: u8) u8 {
    return switch (decimal) {
        0...9 => decimal + 48,
        10...15 => decimal + 55,
        else => unreachable,
    };
}

pub fn cidrToIpv6Range(cidr: []const u8) IPAddressRange {
    var split_it = std.mem.split(u8, cidr, "/");
    const ipaddress = split_it.next().?;
    const netmask = stringToUint8(split_it.next() orelse "128");
    const startDecimal = ipv6ToDecimal(ipaddress) & @truncate(u128, createNetMask(u129, 128, netmask));
    const endDecimal = math.pow(u32, 2, 128 - netmask) + startDecimal - 1;
    return IPAddressRange.init(decimalToIpv6(startDecimal), decimalToIpv6(endDecimal));
}

pub fn ipv6RangeToCidr(allocator: std.mem.Allocator, range: [2][]const u8) ![]Cidr {
    var start = ipv6ToDecimal(range[0]);
    const end = ipv6ToDecimal(range[1]);
    var cidr = std.ArrayList(Cidr).init(allocator);
    while (end >= start) {
        var maxSize: u8 = 128;
        while (maxSize > 0) {
            const mask = @truncate(u128, createNetMask(u129, 128, maxSize - 1));
            if ((start & mask) != start) {
                break;
            }
            maxSize -= 1;
        }
        const diff: u8 = 128 - @floatToInt(u8, math.log2(@intToFloat(f128, end - start + 1)));
        if (maxSize < diff) {
            maxSize = diff;
        }
        try cidr.append(Cidr.init(decimalToIpv6(start), maxSize));
        start += @truncate(u128, math.pow(u129, 2, 128 - maxSize));
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

fn assertIpv4Cidr(actual: Cidr, expected_sections: [4]u8, expected_netmask: u8) !void {
    try assertIpv4(actual.address.v4, expected_sections);
    try testing.expect(actual.netmask == expected_netmask);
}

test "IPv4 to Decimal" {
    try testing.expect(ipv4ToDecimal("192.168.0.1") == 3232235521);
}

test "Decimal to IPv4" {
    var ipv4 = decimalToIpv4(3232235521);
    try assertIpv4(ipv4.v4, .{ 192, 168, 0, 1 });
}

test "Cidr to IPv4 range" {
    var range = cidrToIpv4Range("192.168.0.1/24");
    try assertIpv4(range.start.v4, .{ 192, 168, 0, 0 });
    try assertIpv4(range.end.v4, .{ 192, 168, 0, 255 });
}

test "IPv4 range to cidr" {
    var allocator = testing.allocator;
    var cidr = try ipv4RangeToCidr(allocator, .{ "192.168.0.1", "192.168.0.10" });
    defer allocator.free(cidr);
    try testing.expect(cidr.len == 5);

    try assertIpv4Cidr(cidr[0], .{ 192, 168, 0, 1 }, 32);
    try assertIpv4Cidr(cidr[1], .{ 192, 168, 0, 2 }, 31);
    try assertIpv4Cidr(cidr[2], .{ 192, 168, 0, 4 }, 30);
    try assertIpv4Cidr(cidr[3], .{ 192, 168, 0, 8 }, 31);
    try assertIpv4Cidr(cidr[4], .{ 192, 168, 0, 10 }, 32);
}

test "Print IPv4" {
    const ipv4 = IPAddress{ .v4 = .{ 192, 168, 0, 1 } };
    var buffer: [1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try ipv4.print(fbs.writer());
    try testing.expect(std.mem.eql(u8, fbs.getWritten(), "192.168.0.1"));
}

test "Print IPv4 range" {
    const ipv4Range = IPAddressRange.init(IPAddress{ .v4 = .{ 192, 168, 0, 1 } }, IPAddress{ .v4 = .{ 192, 168, 0, 10 } });
    var buffer: [1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try ipv4Range.print(fbs.writer());
    try testing.expect(std.mem.eql(u8, fbs.getWritten(), "start: 192.168.0.1\nend: 192.168.0.10\n"));
}

test "Print IPv4 cidr" {
    const cidr = Cidr.init(IPAddress{ .v4 = .{ 192, 168, 0, 0 } }, 24);
    var buffer: [1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try cidr.print(fbs.writer());
    try testing.expect(std.mem.eql(u8, fbs.getWritten(), "192.168.0.0/24"));
}

fn assertIpv6Section(actual: [4]u8, expected: []const u8) !void {
    for (expected) |e, i| {
        try testing.expect(actual[i] == e);
    }
}

fn assertIpv6(actual: [8][4]u8, expected: [8][]const u8) !void {
    for (expected) |e, i| {
        try assertIpv6Section(actual[i], e);
    }
}

fn assertIpv6Cidr(actual: Cidr, expected_section: [8][]const u8, expected_netmask: u8) !void {
    try assertIpv6(actual.address.v6, expected_section);
    try testing.expect(actual.netmask == expected_netmask);
}

test "IPv6 to Decimal" {
    try testing.expect(ipv6ToDecimal("2001:4860:4860::8888") == 42541956123769884636017138956568135816);
}

test "Hex to Decimal" {
    var section = hexToIpv6Section(8193);
    try assertIpv6Section(section, "2001");
}

test "Decimal to IPv6" {
    var ipv6 = decimalToIpv6(42541956123769884636017138956568135816);
    try assertIpv6(ipv6.v6, .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8888" });
}

test "IPv6 to Cidr - Simple" {
    var allocator = testing.allocator;
    var cidr = try ipv6RangeToCidr(allocator, .{ "2001:4860:4860:0000:0000:0000:0000:0000", "2001:4860:4860:0000:0000:0000:0000:0001" });
    defer allocator.free(cidr);
    try testing.expect(cidr.len == 1);

    try assertIpv6Cidr(cidr[0], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "0000" }, 127);
}

test "IPv6 to Cidr - Complex" {
    var allocator = testing.allocator;
    var cidr = try ipv6RangeToCidr(allocator, .{ "2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860:0000:0000:0000:1111:1111" });
    defer allocator.free(cidr);
    try testing.expect(cidr.len == 29);

    try assertIpv6Cidr(cidr[0], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8888" }, 125);
    try assertIpv6Cidr(cidr[1], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8890" }, 124);
    try assertIpv6Cidr(cidr[2], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "88A0" }, 123);
    try assertIpv6Cidr(cidr[3], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "88C0" }, 122);
    try assertIpv6Cidr(cidr[4], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8900" }, 120);
    try assertIpv6Cidr(cidr[5], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8A00" }, 119);
    try assertIpv6Cidr(cidr[6], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8C00" }, 118);
    try assertIpv6Cidr(cidr[7], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "9000" }, 116);
    try assertIpv6Cidr(cidr[8], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "A000" }, 115);
    try assertIpv6Cidr(cidr[9], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "C000" }, 114);
    try assertIpv6Cidr(cidr[10], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0001", "0000" }, 112);
    try assertIpv6Cidr(cidr[11], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0002", "0000" }, 111);
    try assertIpv6Cidr(cidr[12], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0004", "0000" }, 110);
    try assertIpv6Cidr(cidr[13], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0008", "0000" }, 109);
    try assertIpv6Cidr(cidr[14], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0010", "0000" }, 108);
    try assertIpv6Cidr(cidr[15], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0020", "0000" }, 107);
    try assertIpv6Cidr(cidr[16], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0040", "0000" }, 106);
    try assertIpv6Cidr(cidr[17], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0080", "0000" }, 105);
    try assertIpv6Cidr(cidr[18], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0100", "0000" }, 104);
    try assertIpv6Cidr(cidr[19], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0200", "0000" }, 103);
    try assertIpv6Cidr(cidr[20], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0400", "0000" }, 102);
    try assertIpv6Cidr(cidr[21], .{ "2001", "4860", "4860", "0000", "0000", "0000", "0800", "0000" }, 101);
    try assertIpv6Cidr(cidr[22], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1000", "0000" }, 104);
    try assertIpv6Cidr(cidr[23], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1100", "0000" }, 108);
    try assertIpv6Cidr(cidr[24], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1110", "0000" }, 112);
    try assertIpv6Cidr(cidr[25], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1111", "0000" }, 116);
    try assertIpv6Cidr(cidr[26], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1111", "1000" }, 120);
    try assertIpv6Cidr(cidr[27], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1111", "1100" }, 124);
    try assertIpv6Cidr(cidr[28], .{ "2001", "4860", "4860", "0000", "0000", "0000", "1111", "1110" }, 127);
}

test "Cidr to IPv6 range" {
    var range = cidrToIpv6Range("2001:4860:4860:0:0:0:0:8888/127");
    try assertIpv6(range.start.v6, .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8888" });
    try assertIpv6(range.end.v6, .{ "2001", "4860", "4860", "0000", "0000", "0000", "0000", "8889" });
}

test "Print IPv6" {
    const ipv4 = IPAddress{ .v6 = .{ .{ '2', '0', '0', '1' }, .{ '4', '8', '6', '0' }, .{ '4', '8', '6', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '8', '8', '8', '8' } } };
    var buffer: [1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try ipv4.print(fbs.writer());
    try testing.expect(std.mem.eql(u8, fbs.getWritten(), "2001:4860:4860:0000:0000:0000:0000:8888"));
}

test "Print IPv6 range" {
    const ipv4Range = IPAddressRange.init(IPAddress{ .v6 = .{ .{ '2', '0', '0', '1' }, .{ '4', '8', '6', '0' }, .{ '4', '8', '6', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '8', '8', '8', '8' } } }, IPAddress{ .v6 = .{ .{ '2', '0', '0', '1' }, .{ '4', '8', '6', '0' }, .{ '4', '8', '6', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '1', '0', '1', '0' }, .{ '8', '8', '8', '8' } } });
    var buffer: [1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try ipv4Range.print(fbs.writer());
    try testing.expect(std.mem.eql(u8, fbs.getWritten(), "start: 2001:4860:4860:0000:0000:0000:0000:8888\nend: 2001:4860:4860:0000:0000:0000:1010:8888\n"));
}

test "Print IPv6 cidr" {
    const cidr = Cidr.init(IPAddress{ .v6 = .{ .{ '2', '0', '0', '1' }, .{ '4', '8', '6', '0' }, .{ '4', '8', '6', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '0', '0', '0', '0' }, .{ '8', '8', '8', '8' } } }, 125);
    var buffer: [1000]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    try cidr.print(fbs.writer());
    try testing.expect(std.mem.eql(u8, fbs.getWritten(), "2001:4860:4860:0000:0000:0000:0000:8888/125"));
}
