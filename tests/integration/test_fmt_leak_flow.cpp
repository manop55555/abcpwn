// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// End-to-end fmt-leak flow: planted printf dump -> find offset ->
// build leak payload -> build write payload. Mirrors the steps a CTF
// player runs after dropping `AAAA%X.%X.%X` into a vulnerable printf.

#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/fmt.hpp"
#include "abcpwn/core/context.hpp"

TEST_CASE("fmt-leak flow: locate offset -> leak payload -> write payload", "[integration][fmt]") {
    using namespace abcpwn::commands::fmt;
    abcpwn::core::Context ctx;

    // Stage 1: parse a representative printf-style dump output.
    // The 4th 32-bit hex word is our 0x41414141 marker; tokens 1-3
    // are typical libc / stack noise.
    const std::string dump = "0x7ffe12345678.0x7f1234567890.0xdeadbeef.0x41414141.0xcafebabe";
    auto idx_opt = find_marker_offset(dump);
    REQUIRE(idx_opt.has_value());
    const std::size_t idx = *idx_opt;
    REQUIRE(idx == 4);

    // Stage 2: turn the discovered index into a leak payload. The
    // dispatcher's FmtCommand --leak goes through the same helper.
    {
        FmtCommand cmd;
        // FmtCommand expects the index as a hex literal in
        // leak_address_hex (per the surface in fmt.hpp).
        cmd.leak_address_hex = "0x4";
        auto r = cmd.run(ctx);
        REQUIRE(r);
        REQUIRE(r->raw_lines.size() == 1);
        REQUIRE(r->raw_lines[0] == "%4$s");
    }

    // Stage 3: build a what-where write payload using the discovered
    // arg index. The payload should embed four target-address slots
    // and a format string that walks the printf counter to each
    // 16-bit half via %hn.
    {
        FmtCommand cmd;
        cmd.write_spec = "0x404040=0xdeadbeef";
        cmd.arg_position = static_cast<std::int64_t>(idx);
        cmd.arch_str = "x86_64";
        auto r = cmd.run(ctx);
        REQUIRE(r);
        REQUIRE(r->raw_lines.size() == 1);
        // Output is escaped hex; the target-address prefix must
        // contain the bottom-three bytes of 0x404040 = 0x40 0x40 0x40.
        REQUIRE(r->raw_lines[0].find("\\x40\\x40\\x40") != std::string::npos);
        // And the format string section contains at least one '%'
        // (the whole payload is escaped-hex, so '%' becomes \x25 and
        // the trailing 'hn' of %hn appears as \x68\x6e).
        REQUIRE(r->raw_lines[0].find("\\x25") != std::string::npos);
        REQUIRE(r->raw_lines[0].find("\\x68\\x6e") != std::string::npos);
    }
}
