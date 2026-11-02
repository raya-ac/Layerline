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

    const child_worker = b.addExecutable(.{
        .name = "child-process-worker",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/testing/child_process_worker.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    b.step("test-tools", "Build native wire-test fixtures (not installed with the server)")
        .dependOn(&b.addInstallArtifact(child_worker, .{}).step);

    const run_cmd = b.addRunArtifact(exe);
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run the HTTP server");
    run_step.dependOn(&run_cmd.step);

    const app_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/app_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_app_tests = b.addRunArtifact(app_tests);

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

    const tls_pem_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tls_pem.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_tls_pem_tests = b.addRunArtifact(tls_pem_tests);

    const key_update_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/native_tls_key_update_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    const static_cache_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/static_cache.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_static_cache_tests = b.addRunArtifact(static_cache_tests);

    const config_loader_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/config_loader.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_config_loader_tests = b.addRunArtifact(config_loader_tests);

    const reactor_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/core/reactor.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_reactor_tests = b.addRunArtifact(reactor_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(key_update_tests).step);
    const certificate_probe = b.addExecutable(.{
        .name = "upstream-certificate-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/upstream_certificate_probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const certificate_checks = b.addSystemCommand(&.{"python3"});
    certificate_checks.addFileArg(b.path("scripts/verify-upstream-certificates.py"));
    certificate_checks.addArtifactArg(certificate_probe);
    b.step("test-upstream-certificates", "Test native certificate policy with disposable OpenSSL chains")
        .dependOn(&certificate_checks.step);
    test_step.dependOn(&certificate_probe.step);
    const upstream_tls_probe = b.addExecutable(.{
        .name = "upstream-tls-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/upstream_tls_probe.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    var previous_tls_check: *std.Build.Step = &upstream_tls_probe.step;
    for ([_][]const u8{ "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256" }) |suite| {
        const checks = b.addSystemCommand(&.{"python3"});
        checks.addFileArg(b.path("scripts/verify-upstream-tls.py"));
        checks.addArtifactArg(upstream_tls_probe);
        checks.addArgs(&.{ "--tls13-suite", suite });
        checks.step.dependOn(previous_tls_check);
        previous_tls_check = &checks.step;
    }
    b.step("test-upstream-tls", "Test the native origin TLS channel against disposable real TLS peers")
        .dependOn(previous_tls_check);
    const https_checks = b.addSystemCommand(&.{"python3"});
    https_checks.addFileArg(b.path("scripts/verify-https-upstreams.py"));
    https_checks.addArtifactArg(exe);
    b.step("test-https-upstreams", "Test authenticated HTTPS proxy traffic, pools, tunnels and reloads")
        .dependOn(&https_checks.step);
    const native_tls_checks = b.addSystemCommand(&.{"python3"});
    native_tls_checks.addFileArg(b.path("scripts/verify-native-tls.py"));
    native_tls_checks.addArtifactArg(exe);
    b.step("test-native-tls", "Test native TLS key updates and closure with independent OpenSSL clients")
        .dependOn(&native_tls_checks.step);
    const tls_diagnostic_checks = b.addSystemCommand(&.{"python3"});
    tls_diagnostic_checks.addFileArg(b.path("scripts/verify-tls-diagnostics.py"));
    tls_diagnostic_checks.addArtifactArg(exe);
    b.step("test-tls-diagnostics", "Test bounded single-line TLS diagnostics with hostile ClientHellos")
        .dependOn(&tls_diagnostic_checks.step);
    const startup_material_checks = b.addSystemCommand(&.{"python3"});
    startup_material_checks.addFileArg(b.path("scripts/verify-startup-materials.py"));
    startup_material_checks.addArtifactArg(exe);
    startup_material_checks.addArtifactArg(child_worker);
    b.step("test-startup-materials", "Test origin trust preflight before certificate/DNS side effects")
        .dependOn(&startup_material_checks.step);
    test_step.dependOn(&upstream_tls_probe.step);
    // Unit roots do not analyze every runtime function in Zig.
    test_step.dependOn(&exe.step);
    const protocol_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/protocol_tests.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(protocol_tests).step);
    test_step.dependOn(&run_app_tests.step);
    test_step.dependOn(&run_config_loader_tests.step);
    test_step.dependOn(&run_h2_tests.step);
    test_step.dependOn(&run_h3_tests.step);
    test_step.dependOn(&run_h3_state_tests.step);
    test_step.dependOn(&run_http_response_tests.step);
    test_step.dependOn(&run_quic_tests.step);
    test_step.dependOn(&run_reactor_tests.step);
    test_step.dependOn(&run_static_cache_tests.step);
    test_step.dependOn(&run_tls_client_hello_tests.step);
    test_step.dependOn(&run_tls13_tests.step);
    test_step.dependOn(&run_tls_pem_tests.step);
}
