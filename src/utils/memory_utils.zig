//! Memory utilities for Neo Zig SDK
//!
//! Provides common memory management utilities including deinit macros,
//! allocator helpers, and type-safe resource cleanup.

const std = @import("std");

pub const MemoryUtils = struct {
    pub fn freeIfAllocated(allocator: std.mem.Allocator, ptr: anytype) void {
        if (@as(?*const anyopaque, @ptrCast(ptr)) != null) {
            allocator.free(ptr);
        }
    }
};

fn deinitField(comptime FieldType: type, field_ptr: anytype, allocator: std.mem.Allocator) void {
    switch (@typeInfo(FieldType)) {
        .Pointer => |ptr_info| {
            if (ptr_info.size == .Slice) {
                const slice = @as(*FieldType, @constCast(@ptrCast(field_ptr)));
                allocator.free(slice.*);
            } else if (@hasDecl(FieldType, "deinit")) {
                const typed_ptr = @as(*FieldType, @constCast(@ptrCast(field_ptr)));
                typed_ptr.*.deinit(allocator);
            }
        },
        .Struct => |struct_info| {
            inline for (struct_info.fields) |nested_field| {
                const NestedType = nested_field.type;
                const nested_ptr = &@field(@as(*FieldType, @constCast(@ptrCast(field_ptr))).*, nested_field.name);
                deinitField(NestedType, nested_ptr, allocator);
            }
        },
        .Optional => |opt_info| {
            const opt_ptr = @as(*FieldType, @constCast(@ptrCast(field_ptr)));
            if (opt_ptr.*) |*value| {
                deinitField(opt_info.child, value, allocator);
            }
        },
        .Array => |array_info| {
            if (array_info.child == u8) {
                const arr_ptr = @as(*FieldType, @constCast(@ptrCast(field_ptr)));
                allocator.free(arr_ptr.*);
            }
        },
        else => {},
    }
}

pub fn generateDeinit(comptime T: type) fn (*T, std.mem.Allocator) void {
    return struct {
        fn deinitImpl(self: *T, allocator: std.mem.Allocator) void {
            const ti = @typeInfo(T);
            switch (ti) {
                .Struct => |struct_info| {
                    inline for (struct_info.fields) |field| {
                        const FieldType = field.type;
                        const field_ptr = &@field(self, field.name);
                        deinitField(FieldType, field_ptr, allocator);
                    }
                },
                else => {},
            }
        }
    }.deinitImpl;
}

pub fn hasStringField(comptime T: type, comptime field_name: []const u8) bool {
    const ti = @typeInfo(T);
    if (ti != .Struct) return false;
    inline for (ti.Struct.fields) |field| {
        if (std.mem.eql(u8, field.name, field_name)) {
            return field.type == []const u8;
        }
    }
    return false;
}

test "generateDeinit basic functionality" {
    const TestStruct = struct {
        name: []const u8,
        value: i32,

        const Self = @This();
    };

    const allocator = std.testing.allocator;

    const test_name = try allocator.dupe(u8, "test");
    defer allocator.free(test_name);

    var test_struct = TestStruct{
        .name = test_name,
        .value = 42,
    };

    const deinit = generateDeinit(TestStruct);
    deinit(&test_struct, allocator);
}

test "generateDeinit with nested struct" {
    const Inner = struct {
        inner_name: []const u8,
        inner_value: i32,
    };

    const Outer = struct {
        outer_name: []const u8,
        inner: Inner,
        outer_value: i32,

        const Self = @This();
    };

    const allocator = std.testing.allocator;

    const outer_name = try allocator.dupe(u8, "outer");
    const inner_name = try allocator.dupe(u8, "inner");
    defer allocator.free(outer_name);
    defer allocator.free(inner_name);

    var outer = Outer{
        .outer_name = outer_name,
        .inner = Inner{ .inner_name = inner_name, .inner_value = 100 },
        .outer_value = 42,
    };

    const deinit = generateDeinit(Outer);
    deinit(&outer, allocator);
}

test "generateDeinit with optional fields" {
    const WithOptional = struct {
        name: []const u8,
        optional_data: ?[]const u8,

        const Self = @This();
    };

    const allocator = std.testing.allocator;

    const name = try allocator.dupe(u8, "test");
    const optional = try allocator.dupe(u8, "optional");
    defer allocator.free(name);
    defer allocator.free(optional);

    var with_optional = WithOptional{
        .name = name,
        .optional_data = optional,
    };

    const deinit = generateDeinit(WithOptional);
    deinit(&with_optional, allocator);
}

test "hasStringField detection" {
    const TestStruct = struct {
        name: []const u8,
        value: i32,
    };

    try std.testing.expect(hasStringField(TestStruct, "name"));
    try std.testing.expect(!hasStringField(TestStruct, "value"));
    try std.testing.expect(!hasStringField(TestStruct, "nonexistent"));
}
