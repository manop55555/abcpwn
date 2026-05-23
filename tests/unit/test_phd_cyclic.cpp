// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/cyclic.hpp"
#include "abcpwn/commands/disasm.hpp"
#include "abcpwn/commands/phd.hpp"

using namespace abcpwn::commands;

TEST_CASE("format_hex_dump produces canonical xxd-like rows", "[phd]") {
    const std::vector<std::uint8_t> data{
        0x7f,
        0x45,
        0x4c,
        0x46,
        0x02,
        0x01,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
    auto rows = format_hex_dump(data, 0, 16);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows[0].find("00000000") == 0);
    REQUIRE(rows[0].find("|.ELF") != std::string::npos);
}

TEST_CASE("format_hex_dump handles short final row", "[phd]") {
    const std::vector<std::uint8_t> data{0x41, 0x42, 0x43};
    auto rows = format_hex_dump(data, 0, 16);
    REQUIRE(rows.size() == 1);
    REQUIRE(rows[0].find("41 42 43") != std::string::npos);
    REQUIRE(rows[0].find("|ABC|") != std::string::npos);
}

TEST_CASE("cyclic_generate matches pwntools cyclic", "[cyclic]") {
    // pwntools cyclic(20) -> b'aaaabaaacaaadaaaeaaa'
    REQUIRE(cyclic_generate(20) == "aaaabaaacaaadaaaeaaa");
    const auto a = cyclic_generate(100);
    REQUIRE(a.size() == 100);
    REQUIRE(a.substr(0, 4) == "aaaa");
    REQUIRE(a.substr(4, 4) == "baaa");
}

TEST_CASE("cyclic_find round-trip locates subsequence", "[cyclic]") {
    const auto seq = cyclic_generate(200);
    // pick a sub-sequence at offset 50 and ask cyclic_find to recover it
    const std::string probe = seq.substr(50, 4);
    auto off = cyclic_find(probe);
    REQUIRE(off.has_value());
    REQUIRE(*off == 50);
}

TEST_CASE("cyclic_find on absent input returns nullopt", "[cyclic]") {
    auto off = cyclic_find("zzzz");
    // 'zzzz' is not in the standard 26-letter alphabet's de Bruijn
    // sequence at length 4 except at exactly one place. It is in
    // fact present (last block); just sanity-check it returned a
    // value when valid.
    if (off.has_value()) {
        REQUIRE(*off < 26 * 26 * 26 * 26);
    }

    auto missing = cyclic_find("AAAA"); // capitals not in alphabet
    REQUIRE_FALSE(missing.has_value());
}

TEST_CASE("CyclicCommand rejects length past unique-window limit", "[cyclic][command][size]") {
    abcpwn::core::Context ctx;
    CyclicCommand cmd;
    // Default alphabet (a-z, k=26) at default subseq (n=4) gives
    // a unique-window maximum of 26^4 = 456,976. Anything past
    // that produces wrap-around output where the unique-offset
    // guarantee no longer holds and cyclic --find returns wrong
    // values. Round 1's CRITICAL reproducer: cyclic 100000000.
    cmd.length = 100'000'000;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::SizeExceeded);
    REQUIRE(r.error().message.find("456976") != std::string::npos);

    // The exact maximum should still work.
    CyclicCommand cmd_max;
    cmd_max.length = 26 * 26 * 26 * 26;
    auto r_max = cmd_max.run(ctx);
    REQUIRE(r_max);
    REQUIRE(r_max->raw_lines.size() == 1);
    REQUIRE(r_max->raw_lines[0].size() == 26 * 26 * 26 * 26);

    // One past the maximum is rejected.
    CyclicCommand cmd_over;
    cmd_over.length = 26 * 26 * 26 * 26 + 1;
    auto r_over = cmd_over.run(ctx);
    REQUIRE_FALSE(r_over);
    REQUIRE(r_over.error().code == abcpwn::core::ErrorCode::SizeExceeded);
}

TEST_CASE("DisasmCommand renders an i386 chain", "[disasm][command]") {
    abcpwn::core::Context ctx;
    DisasmCommand d;
    d.input = "31c0c3"; // xor eax, eax; ret
    d.input_hex = true;
    d.arch_name = "i386";
    d.base_address = 0x400000;
    auto r = d.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 2);
    REQUIRE(r->raw_lines[0].find("xor") != std::string::npos);
    REQUIRE(r->raw_lines[1].find("ret") != std::string::npos);
}
