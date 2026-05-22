// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <array>
#include <cstdint>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/arch/disasm.hpp"

TEST_CASE("disasm x86_64 short prelude", "[!benchmark][disasm]") {
    // ~50 bytes of representative x86_64 prologue / epilogue mix.
    static constexpr std::array<std::uint8_t, 48> prog = {
        0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0xc7, 0x45, 0xfc, 0x00,
        0x00, 0x00, 0x00, 0x8b, 0x45, 0xfc, 0x83, 0xc0, 0x01, 0x89, 0x45, 0xfc,
        0x83, 0x7d, 0xfc, 0x0a, 0x7e, 0xf0, 0x8b, 0x45, 0xfc, 0xc9, 0xc3, 0x90,
        0x90, 0x90, 0x90, 0x90, 0x5f, 0xc3, 0x5e, 0xc3, 0x58, 0xc3, 0x0f, 0x05,
    };
    abcpwn::arch::DisasmOptions opts;
    opts.arch = abcpwn::arch::Arch::X86_64;

    BENCHMARK("disasm x86_64 / 48 bytes") {
        auto r = abcpwn::arch::disassemble(std::span<const std::uint8_t>(prog.data(), prog.size()),
                                           opts);
        return r ? r->size() : 0U;
    };
}
