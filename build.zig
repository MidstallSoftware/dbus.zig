const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const linkage = b.option(std.builtin.LinkMode, "linkage", "whether to statically or dynamically link the library") orelse @as(std.builtin.LinkMode, if (target.result.isGnuLibC()) .dynamic else .static);

    const dbusSource = b.dependency("dbus", .{});

    const expat = b.dependency("expat", .{
        .target = target,
        .optimize = optimize,
        .linkage = linkage,
    });

    const archDepsHeader = b.addConfigHeader(.{
        .style = .{
            .cmake = dbusSource.path("dbus/dbus-arch-deps.h.in"),
        },
        .include_path = "dbus/dbus-arch-deps.h",
    }, .{
        .DBUS_VERSION = "1.14.10",
        .DBUS_MAJOR_VERSION = "1",
        .DBUS_MINOR_VERSION = "14",
        .DBUS_MICRO_VERSION = "10",
        .DBUS_INT64_TYPE = "long long",
        .DBUS_INT32_TYPE = "int",
        .DBUS_INT16_TYPE = "short",
        .DBUS_SIZEOF_VOID_P = "sizeof (void*)",
        .DBUS_INT64_CONSTANT = "(val##LL)",
        .DBUS_UINT64_CONSTANT = "(val##ULL)",
    });

    const configHeader = b.addWriteFile("config.h", blk: {
        var output = std.ArrayList(u8).init(b.allocator);
        defer output.deinit();

        try output.appendSlice(
            \\#pragma once
            \\
            \\#define HAVE_ERRNO_H
            \\#include <stdarg.h>
            \\#include <stdint.h>
            \\#include <unistd.h>
            \\
            \\#define VERSION "1.14.10"
            \\#define SOVERSION "3.38.0"
            \\#define DBUS_DAEMON_NAME "\"dbus\""
            \\#define DBUS_COMPILATION
            \\#define DBUS_VA_COPY va_copy
            \\#define DBUS_SESSION_BUS_CONNECT_ADDRESS "\"autolaunch:\""
            \\#define DBUS_SYSTEM_BUS_DEFAULT_ADDRESS "\"unix:tmpdir=/tmp\""
            \\#define DBUS_ENABLE_CHECKS
            \\#define DBUS_ENABLE_ASSERT
            \\#define HAVE_ALLOCA_H
            \\
        );

        if (target.result.abi == .gnu) {
            try output.appendSlice(
                \\#define __USE_GNU
                \\
            );
        }

        if (target.result.os.tag == .windows) {
            try output.appendSlice(
                \\#define DBUS_WIN
                \\
            );
        } else {
            try output.appendSlice(b.fmt(
                \\#define _GNU_SOURCE
                \\#define HAVE_SYSLOG_H
                \\#define HAVE_SOCKLEN_T
                \\#define HAVE_SYS_RANDOM_H
                \\
                \\#include <signal.h>
                \\#include <sys/types.h>
                \\
                \\#define DBUS_UNIX
                \\#define HAVE_GETPWNAM_R
                \\#define DBUS_PREFIX "{s}"
                \\#define DBUS_BINDIR "{s}"
                \\#define DBUS_DATADIR "{s}"
                \\#define DBUS_MACHINE_UUID_FILE "{s}"
                \\#define DBUS_SYSTEM_CONFIG_FILE "{s}"
                \\#define DBUS_SESSION_CONFIG_FILE "{s}"
                \\
            , .{
                b.install_prefix,
                b.getInstallPath(.bin, ""),
                b.getInstallPath(.prefix, "usr/share"),
                b.getInstallPath(.prefix, "var/lib/dbus/machine-id"),
                b.getInstallPath(.prefix, "usr/share/dbus-1/system.conf"),
                b.getInstallPath(.prefix, "usr/share/dbus-1/session.conf"),
            }));
        }

        if (target.result.os.tag == .linux) {
            try output.appendSlice(
                \\#define HAVE_APPARMOR
                \\#define HAVE_APPARMOR_2_10
                \\#define HAVE_LIBAUDIT
                \\#define HAVE_SELINUX
                \\#define DBUS_HAVE_LINUX_EPOLL
                \\
            );
        }

        break :blk try output.toOwnedSlice();
    });

    const libdbus = std.Build.Step.Compile.create(b, .{
        .name = "dbus-1",
        .root_module = .{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        },
        .kind = .lib,
        .linkage = linkage,
        .version = .{
            .major = 3,
            .minor = 38,
            .patch = 0,
        },
    });

    libdbus.addConfigHeader(archDepsHeader);
    libdbus.addIncludePath(configHeader.getDirectory());
    libdbus.addIncludePath(dbusSource.path("."));

    libdbus.addCSourceFiles(.{
        .root = dbusSource.path("dbus"),
        .files = &.{
            "dbus-address.c",
            "dbus-asv-util.c",
            "dbus-auth.c",
            "dbus-bus.c",
            "dbus-connection.c",
            "dbus-credentials.c",
            "dbus-dataslot.c",
            "dbus-errors.c",
            "dbus-file.c",
            "dbus-hash.c",
            "dbus-internals.c",
            "dbus-keyring.c",
            "dbus-list.c",
            "dbus-marshal-basic.c",
            "dbus-marshal-byteswap.c",
            "dbus-marshal-header.c",
            "dbus-marshal-recursive.c",
            "dbus-marshal-validate.c",
            "dbus-mainloop.c",
            "dbus-memory.c",
            "dbus-mempool.c",
            "dbus-message.c",
            "dbus-message-util.c",
            "dbus-misc.c",
            "dbus-nonce.c",
            "dbus-object-tree.c",
            "dbus-pending-call.c",
            "dbus-pollable-set.c",
            "dbus-pipe.c",
            "dbus-resources.c",
            "dbus-server-debug-pipe.c",
            "dbus-server-socket.c",
            "dbus-server.c",
            "dbus-sha.c",
            "dbus-signature.c",
            "dbus-string.c",
            "dbus-string-util.c",
            "dbus-syntax.c",
            "dbus-sysdeps.c",
            "dbus-sysdeps-util.c",
            "dbus-threads.c",
            "dbus-timeout.c",
            "dbus-transport-socket.c",
            "dbus-transport.c",
            "dbus-userdb.c",
            "dbus-userdb-util.c",
            "dbus-watch.c",
        },
    });

    if (target.result.os.tag == .windows) {
        libdbus.addCSourceFiles(.{
            .root = dbusSource.path("dbus"),
            .files = &.{
                "dbus-backtrace-win.c",
                "dbus-file-win.c",
                "dbus-pipe-win.c",
                "dbus-init-win.cpp",
                "dbus-server-win.c",
                "dbus-sysdeps-thread-win.c",
                "dbus-sysdeps-util-win.c",
                "dbus-sysdeps-win.c",
                "dbus-transport-win.c",
            },
        });
    } else {
        libdbus.addCSourceFiles(.{
            .root = dbusSource.path("dbus"),
            .files = &.{
                "dbus-uuidgen.c",
                "dbus-server-unix.c",
                "dbus-pollable-set-poll.c",
                "dbus-pollable-set-epoll.c",
                "dbus-file-unix.c",
                "dbus-pipe-unix.c",
                "dbus-sysdeps-pthread.c",
                "dbus-sysdeps-util-unix.c",
                "dbus-transport-unix.c",
            },
        });

        libdbus.addCSourceFile(.{
            .file = .{
                .path = b.pathFromRoot("src/dbus-sysdeps-unix.c"),
            },
        });
    }

    {
        const headers: []const []const u8 = &.{
            "dbus/dbus-address.h",
            "dbus/dbus-bus.h",
            "dbus/dbus-connection.h",
            "dbus/dbus-errors.h",
            "dbus/dbus-macros.h",
            "dbus/dbus-memory.h",
            "dbus/dbus-message.h",
            "dbus/dbus-misc.h",
            "dbus/dbus-pending-call.h",
            "dbus/dbus-protocol.h",
            "dbus/dbus-server.h",
            "dbus/dbus-shared.h",
            "dbus/dbus-signature.h",
            "dbus/dbus-syntax.h",
            "dbus/dbus-threads.h",
            "dbus/dbus-types.h",
            "dbus/dbus.h",
        };

        for (headers) |header| {
            const install_file = b.addInstallFileWithDir(dbusSource.path(header), .header, header);
            b.getInstallStep().dependOn(&install_file.step);
            libdbus.installed_headers.append(&install_file.step) catch @panic("OOM");
        }
    }

    libdbus.installConfigHeader(archDepsHeader, .{});

    b.installArtifact(libdbus);

    const dbusDaemon = b.addExecutable(.{
        .name = "dbus-daemon",
        .target = target,
        .optimize = optimize,
        .linkage = linkage,
        .link_libc = true,
    });

    dbusDaemon.addConfigHeader(archDepsHeader);
    dbusDaemon.addIncludePath(configHeader.getDirectory());
    dbusDaemon.addIncludePath(dbusSource.path("."));
    dbusDaemon.linkLibrary(expat.artifact("expat"));
    dbusDaemon.linkLibrary(libdbus);

    dbusDaemon.addCSourceFiles(.{
        .root = dbusSource.path("bus"),
        .files = &.{
            "activation.c",
            "apparmor.c",
            "audit.c",
            "bus.c",
            "config-loader-expat.c",
            "config-parser-common.c",
            "config-parser.c",
            "connection.c",
            "containers.c",
            "desktop-file.c",
            "dispatch.c",
            "driver.c",
            "expirelist.c",
            "main.c",
            "policy.c",
            "selinux.c",
            "services.c",
            "signals.c",
            "stats.c",
            "test.c",
            "utils.c",
        },
    });

    if (target.result.os.tag == .linux) {
        const apparmor = b.dependency("apparmor", .{
            .target = target,
            .optimize = optimize,
            .linkage = linkage,
        });

        dbusDaemon.linkLibrary(apparmor.artifact("apparmor"));

        const selinux = b.dependency("selinux", .{
            .target = target,
            .optimize = optimize,
            .linkage = linkage,
        });

        dbusDaemon.linkLibrary(selinux.artifact("selinux"));

        const libaudit = b.dependency("libaudit", .{
            .target = target,
            .optimize = optimize,
            .linkage = linkage,
        });

        dbusDaemon.linkLibrary(libaudit.artifact("audit"));

        const libcap = b.dependency("libcap-ng", .{
            .target = target,
            .optimize = optimize,
            .linkage = linkage,
        });

        dbusDaemon.linkLibrary(libcap.artifact("cap-ng"));

        dbusDaemon.addCSourceFile(.{
            .file = dbusSource.path("bus/dir-watch-inotify.c"),
        });
    }

    b.installArtifact(dbusDaemon);
}
