const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "layerline",
        .root_module = exe_module,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the HTTP server");
    run_step.dependOn(&run_cmd.step);

    const h3_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/h3_native.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_h3_tests = b.addRunArtifact(h3_tests);

    const quic_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/quic_native.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_quic_tests = b.addRunArtifact(quic_tests);

    const tls13_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tls13_native.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tls13_tests = b.addRunArtifact(tls13_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_h3_tests.step);
    test_step.dependOn(&run_quic_tests.step);
    test_step.dependOn(&run_tls13_tests.step);
}
