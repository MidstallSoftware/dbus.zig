const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const linkage = b.option(std.Build.Step.Compile.Linkage, "linkage", "whether to statically or dynamically link the library") orelse .static;

    const dbusSource = b.dependency("dbus", .{});

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
            \\
            \\#define VERSION "1.14.10"
            \\#define SOVERSION "3.38.0"
            \\#define DBUS_COMPILATION
            \\#define DBUS_VA_COPY va_copy
            \\#define DBUS_SESSION_BUS_CONNECT_ADDRESS "\"autolaunch:\""
            \\#define DBUS_SYSTEM_BUS_DEFAULT_ADDRESS "\"unix:tmpdir=/tmp\""
            \\#define DBUS_ENABLE_CHECKS
            \\#define DBUS_ENABLE_ASSERT
            \\
        );

        if (target.result.os.tag == .windows) {
            try output.appendSlice(
                \\#define DBUS_WIN
                \\
            );
        } else {
            try output.appendSlice(
                \\#define _GNU_SOURCE
                \\#define HAVE_SYSLOG_H
                \\#define HAVE_SOCKLEN_T
                \\
                \\#include <sys/types.h>
                \\
                \\struct ucred {
                \\  pid_t pid;
                \\  uid_t uid;
                \\  gid_t gid;
                \\};
                \\
                \\#define DBUS_UNIX
                \\#define HAVE_GETPWNAM_R
                \\#define DBUS_PREFIX "/"
                \\#define DBUS_BINDIR "/bin"
                \\#define DBUS_DATADIR "/usr/share"
                \\#define DBUS_MACHINE_UUID_FILE "/var/lib/dbus/machine-id"
                \\#define DBUS_SYSTEM_CONFIG_FILE "/usr/share/dbus-1/system.conf"
                \\#define DBUS_SESSION_CONFIG_FILE "/usr/share/dbus-1/session.conf"
                \\
            );
        }

        if (target.result.os.tag == .linux) {
            try output.appendSlice(
                \\#define HAVE_LIBAUDIT
                \\#define HAVE_SELINUX
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
        .files = &.{
            dbusSource.path("dbus/dbus-address.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-auth.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-bus.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-connection.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-credentials.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-dataslot.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-errors.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-file.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-hash.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-internals.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-keyring.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-list.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-marshal-basic.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-marshal-byteswap.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-marshal-header.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-marshal-recursive.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-marshal-validate.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-memory.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-mempool.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-message.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-misc.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-nonce.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-object-tree.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-pending-call.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-pipe.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-resources.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-server-debug-pipe.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-server-socket.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-server.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-sha.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-signature.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-string.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-syntax.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-sysdeps.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-threads.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-timeout.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-transport-socket.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-transport.c").getPath(dbusSource.builder),
            dbusSource.path("dbus/dbus-watch.c").getPath(dbusSource.builder),
        },
    });

    if (target.result.os.tag == .windows) {
        libdbus.addCSourceFiles(.{
            .files = &.{
                dbusSource.path("dbus/dbus-backtrace-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-file-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-pipe-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-init-win.cpp").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-server-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-sysdeps-thread-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-sysdeps-util-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-sysdeps-win.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-transport-win.c").getPath(dbusSource.builder),
            },
        });
    } else {
        libdbus.addCSourceFiles(.{
            .files = &.{
                dbusSource.path("dbus/dbus-uuidgen.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-server-unix.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-file-unix.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-pipe-unix.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-sysdeps-pthread.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-sysdeps-util-unix.c").getPath(dbusSource.builder),
                b.pathFromRoot("src/dbus-sysdeps-unix.c"),
                dbusSource.path("dbus/dbus-userdb.c").getPath(dbusSource.builder),
                dbusSource.path("dbus/dbus-transport-unix.c").getPath(dbusSource.builder),
            },
        });
    }

    b.installArtifact(libdbus);
}