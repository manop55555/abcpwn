// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <array>
#include <cstdint>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/arch/disasm.hpp"
#include "abcpwn/arch/syscalls.hpp"

TEST_CASE("arch_from_string handles common aliases", "[arch]") {
    using namespace abcpwn::arch;
    REQUIRE(*arch_from_string("amd64") == Arch::X86_64);
    REQUIRE(*arch_from_string("X86_64") == Arch::X86_64);
    REQUIRE(*arch_from_string("arm64") == Arch::Aarch64);
    REQUIRE(*arch_from_string("rv64") == Arch::Riscv64);
    REQUIRE_FALSE(arch_from_string("not-an-arch").has_value());
}

TEST_CASE("disasm x86_64 nop chain", "[arch][disasm]") {
    using namespace abcpwn::arch;
    // 5 x86_64 NOPs.
    const std::array<std::uint8_t, 5> bytes{0x90, 0x90, 0x90, 0x90, 0x90};
    DisasmOptions opts;
    opts.arch = Arch::X86_64;
    opts.base_address = 0x1000;
    auto r = disassemble(bytes, opts);
    REQUIRE(r);
    REQUIRE(r->size() == 5);
    REQUIRE((*r)[0].address == 0x1000);
    REQUIRE((*r)[0].mnemonic == "nop");
    REQUIRE((*r)[4].address == 0x1004);
}

TEST_CASE("disasm i386 xor + ret", "[arch][disasm]") {
    using namespace abcpwn::arch;
    // 31 c0    xor eax, eax
    // c3       ret
    const std::array<std::uint8_t, 3> bytes{0x31, 0xc0, 0xc3};
    DisasmOptions opts;
    opts.arch = Arch::X86;
    auto r = disassemble(bytes, opts);
    REQUIRE(r);
    REQUIRE(r->size() == 2);
    REQUIRE((*r)[0].mnemonic == "xor");
    REQUIRE((*r)[1].mnemonic == "ret");
}

TEST_CASE("disasm unknown arch returns Unsupported", "[arch][disasm]") {
    using namespace abcpwn::arch;
    DisasmOptions opts;
    opts.arch = Arch::Unknown;
    auto r = disassemble(std::span<const std::uint8_t>{}, opts);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::Unsupported);
}

TEST_CASE("syscall lookup x86_64", "[arch][syscalls]") {
    using namespace abcpwn::arch::syscalls;
    using namespace abcpwn::arch;
    REQUIRE(*by_name(Arch::X86_64, "execve") == 59);
    REQUIRE(*by_name(Arch::X86_64, "exit") == 60);
    REQUIRE(*by_number(Arch::X86_64, 0) == "read");
    REQUIRE_FALSE(by_name(Arch::X86_64, "not_a_syscall").has_value());
}

TEST_CASE("syscall lookup x86 differs from x86_64", "[arch][syscalls]") {
    using namespace abcpwn::arch::syscalls;
    using namespace abcpwn::arch;
    // x86 execve is 11, x86_64 is 59.
    REQUIRE(*by_name(Arch::X86, "execve") == 11);
    REQUIRE(*by_name(Arch::X86_64, "execve") == 59);
}
