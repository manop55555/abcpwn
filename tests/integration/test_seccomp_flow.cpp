// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// End-to-end seccomp flow: decode a known cBPF filter blob from its
// hex encoding -> disassemble -> verify the dump includes the
// expected sys_number prelude, the syscall-name comments, and the
// ALLOW / KILL tail.

#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/commands/seccomp.hpp"
#include "abcpwn/core/context.hpp"

TEST_CASE("seccomp flow: hex decode -> bpf decode -> disassemble", "[integration][seccomp]") {
    // Canonical "allow execve only" filter, the same prelude the
    // unit-level test_sandbox_libc covers. The flow here pipes it
    // through the actual command surface as a hex argument, which
    // is how a CTF player feeds a filter extracted via gdb.
    const std::string filter_hex = "20000000"
                                   "00000000" // A = sys_number
                                   "15000100"
                                   "3b000000" // if (A == 0x3b /* SYS_execve */) goto 3
                                   "06000000"
                                   "0000ff7f" // return ALLOW
                                   "06000000"
                                   "00000000"; // return KILL

    auto bytes = abcpwn::commands::encoding::hex_decode(filter_hex);
    REQUIRE(bytes);

    auto decoded = abcpwn::commands::seccomp::decode_bpf(*bytes);
    REQUIRE(decoded);
    REQUIRE(decoded->size() == 4);

    const auto lines =
        abcpwn::commands::seccomp::disassemble_bpf(*decoded, abcpwn::arch::Arch::X86_64);
    REQUIRE(lines.size() == 4);
    REQUIRE(lines[0].find("A = sys_number") != std::string::npos);
    REQUIRE(lines[1].find("if (A == 0x3b)") != std::string::npos);
    REQUIRE(lines[1].find("SYS_execve") != std::string::npos);
    REQUIRE(lines[2].find("return ALLOW") != std::string::npos);
    REQUIRE(lines[3].find("return KILL") != std::string::npos);

    // Plus the command surface itself runs through the dispatcher
    // layer with the same hex input.
    abcpwn::core::Context ctx;
    abcpwn::commands::seccomp::SeccompCommand cmd;
    cmd.action = "disasm";
    cmd.input = filter_hex;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->summary.has_value());
    REQUIRE(r->summary->find("4 BPF") != std::string::npos);
}
