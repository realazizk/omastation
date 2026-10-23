const std = @import("std");

pub const system_libs = [_][]const u8{ "ssl", "crypto", "pam", "va", "va-drm", "xkbcommon", "opus", "fdk-aac", "gsm", "fuse3", "pipewire-0.3" };

// For translate-c: headers outside /usr/include.
const system_include_dirs = [_][]const u8{ "/usr/include/pipewire-0.3", "/usr/include/spa-0.2" };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const tc = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
    });
    for (system_include_dirs) |d| tc.addSystemIncludePath(.{ .cwd_relative = d });
    const c_mod = tc.createModule();

    const lib_mod = b.addModule("omastation", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    lib_mod.addImport("c", c_mod);
    for (system_libs) |l| lib_mod.linkSystemLibrary(l, .{});

    // Wayland bindings generated from protocols/*.xml.
    const wl_protocols_mod = addWaylandProtocols(b);
    lib_mod.addImport("wl_protocols", wl_protocols_mod);

    const exe = b.addExecutable(.{
        .name = "omastation",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "omastation", .module = lib_mod },
                .{ .name = "c", .module = c_mod },
            },
        }),
    });
    for (system_libs) |l| exe.root_module.linkSystemLibrary(l, .{});
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();
    b.step("run", "Run the server").dependOn(&run_cmd.step);

    const test_filters = b.option([]const []const u8, "test-filter", "unit tests: only those whose name contains this") orelse &.{};
    const lib_tests = b.addTest(.{ .root_module = lib_mod, .filters = test_filters });
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&b.addRunArtifact(lib_tests).step);
    const exe_tests = b.addTest(.{ .name = "main", .root_module = exe.root_module });
    test_step.dependOn(&b.addRunArtifact(exe_tests).step);

}

const wl_protocol_xmls = [_][]const u8{
    "protocols/wayland.xml",
    "protocols/linux-dmabuf-v1.xml",
    "protocols/ext-image-capture-source-v1.xml",
    "protocols/ext-image-copy-capture-v1.xml",
    "protocols/ext-data-control-v1.xml",
    "protocols/wlr-screencopy-unstable-v1.xml",
    "protocols/wlr-virtual-pointer-unstable-v1.xml",
    "protocols/virtual-keyboard-unstable-v1.xml",
};

fn addWaylandProtocols(b: *std.Build) *std.Build.Module {
    const scanner = b.addExecutable(.{
        .name = "wl-scanner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wl/scanner.zig"),
            .target = b.graph.host,
            .optimize = .Debug,
        }),
    });
    const gen = b.addRunArtifact(scanner);
    const out = gen.addOutputFileArg("wl_protocols.zig");
    for (wl_protocol_xmls) |x| gen.addFileArg(b.path(x));
    b.step("wl-gen", "Generate the Wayland protocol bindings (inspect with --verbose)").dependOn(&gen.step);
    return b.createModule(.{ .root_source_file = out });
}
