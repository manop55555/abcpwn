// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/fmt.hpp"
#include "abcpwn/core/context.hpp"

using namespace abcpwn::commands::fmt;

TEST_CASE("find_marker_offset locates 0x41414141 in a printf-style dump", "[fmt]") {
    // From e.g. printf("AAAA%X.%X.%X.%X.%X") output
    auto idx = find_marker_offset("0xdeadbeef.0xcafe.0x41414141.0x1");
    REQUIRE(idx.has_value());
    REQUIRE(*idx == 3);
}

TEST_CASE("find_marker_offset works without 0x prefixes", "[fmt]") {
    auto idx = find_marker_offset("deadbeef 41414141 1234");
    REQUIRE(idx.has_value());
    REQUIRE(*idx == 2);
}

TEST_CASE("find_marker_offset returns nullopt when marker absent", "[fmt]") {
    auto idx = find_marker_offset("0x1.0x2.0x3");
    REQUIRE_FALSE(idx.has_value());
}

TEST_CASE("build_leak_payload emits %N$s by default", "[fmt]") {
    REQUIRE(build_leak_payload(6) == "%6$s");
    REQUIRE(build_leak_payload(7, /*as_string=*/false) == "%7$p");
}

TEST_CASE("build_write_payload requires arg_index", "[fmt]") {
    WriteSpec ws;
    ws.target_address = 0x404040;
    ws.value = 0xdeadbeef;
    ws.arg_index = 0;
    auto r = build_write_payload(ws);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::InvalidInput);
}

TEST_CASE("build_write_payload prepends four target-address slots on x86_64", "[fmt]") {
    WriteSpec ws;
    ws.target_address = 0x404040;
    ws.value = 0xdeadbeef;
    ws.arg_index = 8;
    ws.arch = abcpwn::arch::Arch::X86_64;
    auto r = build_write_payload(ws);
    REQUIRE(r);
    // Four 8-byte addresses = 32 bytes at the start, then the format string.
    REQUIRE(r->size() >= 32);
    // The first 8 bytes should encode 0x404040 (little-endian).
    REQUIRE((*r)[0] == 0x40);
    REQUIRE((*r)[1] == 0x40);
    REQUIRE((*r)[2] == 0x40);
    // Last bytes should look like format-string ascii (contain '%').
    bool has_percent = false;
    for (auto b : *r) {
        if (b == '%') {
            has_percent = true;
            break;
        }
    }
    REQUIRE(has_percent);
}

TEST_CASE("FmtCommand --find-offset reports the index", "[fmt][command]") {
    abcpwn::core::Context ctx;
    FmtCommand cmd;
    cmd.find_offset_dump = "0xff.0xee.0x41414141";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0] == "offset: 3");
}

TEST_CASE("FmtCommand --leak builds a %N$s payload", "[fmt][command]") {
    abcpwn::core::Context ctx;
    FmtCommand cmd;
    cmd.leak_address_hex = "0x6";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0] == "%6$s");
}

TEST_CASE("FmtCommand without any action is a usage error", "[fmt][command]") {
    abcpwn::core::Context ctx;
    FmtCommand cmd;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

TEST_CASE("FmtCommand --write surface returns escaped hex string", "[fmt][command]") {
    abcpwn::core::Context ctx;
    FmtCommand cmd;
    cmd.write_spec = "0x404040=0xdeadbeef";
    cmd.arg_position = 8;
    cmd.arch_str = "x86_64";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0].starts_with("\\x"));
    REQUIRE(r->raw_lines[0].find("\\x40\\x40\\x40") != std::string::npos);
}
