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

    const http_response_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/http_response.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_http_response_tests = b.addRunArtifact(http_response_tests);

    const h3_state_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/h3_state.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_h3_state_tests = b.addRunArtifact(h3_state_tests);

    const h2_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/h2_native.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_h2_tests = b.addRunArtifact(h2_tests);

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

    const tls_client_hello_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tls_client_hello.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tls_client_hello_tests = b.addRunArtifact(tls_client_hello_tests);

    const reactor_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/reactor.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_reactor_tests = b.addRunArtifact(reactor_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_h2_tests.step);
    test_step.dependOn(&run_h3_tests.step);
    test_step.dependOn(&run_h3_state_tests.step);
    test_step.dependOn(&run_http_response_tests.step);
    test_step.dependOn(&run_quic_tests.step);
    test_step.dependOn(&run_reactor_tests.step);
    test_step.dependOn(&run_tls_client_hello_tests.step);
    test_step.dependOn(&run_tls13_tests.step);
}
