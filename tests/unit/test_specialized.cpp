// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/aslr_bypass.hpp"
#include "abcpwn/commands/dynelf.hpp"
#include "abcpwn/commands/ret2dl.hpp"
#include "abcpwn/commands/srop.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

} // namespace

// --- srop --------------------------------------------------------------------

TEST_CASE("serialize_frame is exactly 248 bytes on x86_64", "[srop]") {
    abcpwn::commands::srop::FrameX86_64 f;
    f.rax = 0x3b;
    f.rdi = 0x600000;
    f.rip = 0xdeadbeef;
    f.rsp = 0xcafebabe;
    auto bytes = abcpwn::commands::srop::serialize_frame(f);
    REQUIRE(bytes.size() == 248);
}

TEST_CASE("SropCommand builds a syscall frame for x86_64", "[srop][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::srop::SropCommand cmd;
    cmd.syscall_number = 59;       // execve
    cmd.syscall_args = {0x600000}; // /bin/sh string addr
    cmd.rip = 0x401000;            // syscall gadget
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    // 248 bytes * 2 hex chars
    REQUIRE(r->raw_lines[0].size() == 496);
}

TEST_CASE("SropCommand rejects non-x86_64", "[srop][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::srop::SropCommand cmd;
    cmd.arch_str = "arm64";
    cmd.syscall_number = 0;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::Unsupported);
}

// --- ret2dl ------------------------------------------------------------------

TEST_CASE("Ret2dlCommand reports plt / dynsym offsets on hello-hardened", "[ret2dl][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::ret2dl::Ret2dlCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.symbol = "strcpy"; // present in the fixture
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool seen_plt = false;
    bool seen_dynsym = false;
    bool seen_symbol = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == ".plt")
                seen_plt = true;
            if (f.title == ".dynsym")
                seen_dynsym = true;
            if (f.title.find("strcpy") != std::string::npos)
                seen_symbol = true;
        }
    }
    REQUIRE(seen_plt);
    REQUIRE(seen_dynsym);
    REQUIRE(seen_symbol);
}

TEST_CASE("Ret2dlCommand rejects non-ELF", "[ret2dl][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::ret2dl::Ret2dlCommand cmd;
    cmd.target = "/dev/null"; // not a regular file
    cmd.symbol = "anything";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
}

// --- dynelf -----------------------------------------------------------------

TEST_CASE("parse_leak_arg parses addr=hex pairs", "[dynelf]") {
    auto r = abcpwn::commands::dynelf::parse_leak_arg("0x7f1234567890=cafebabe");
    REQUIRE(r);
    REQUIRE(r->address == 0x7f1234567890ULL);
    REQUIRE(r->bytes.size() == 4);
    REQUIRE(r->bytes[0] == 0xca);
}

TEST_CASE("parse_leak_arg rejects malformed input", "[dynelf]") {
    REQUIRE_FALSE(abcpwn::commands::dynelf::parse_leak_arg("no-equals"));
    REQUIRE_FALSE(abcpwn::commands::dynelf::parse_leak_arg("xyz=cafe"));
    REQUIRE_FALSE(abcpwn::commands::dynelf::parse_leak_arg("0x1234=zz"));
}

TEST_CASE("DynelfCommand reports leak summary", "[dynelf][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::dynelf::DynelfCommand cmd;
    cmd.leaks = {"0x1234=deadbeef", "0x5678=cafebabe"};
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    REQUIRE(r->sections[0].findings.size() >= 2);
}

TEST_CASE("DynelfCommand without leaks is a usage error", "[dynelf][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::dynelf::DynelfCommand cmd;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

// --- aslr-bypass ------------------------------------------------------------

TEST_CASE("AslrBypassCommand --brute-force reports attempt counts", "[aslr][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::aslr_bypass::AslrBypassCommand cmd;
    cmd.brute_force = true;
    cmd.entropy_bits = 16;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool saw_expected = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "expected attempts")
                saw_expected = true;
        }
    }
    REQUIRE(saw_expected);
}

TEST_CASE("AslrBypassCommand without any strategy is a usage error", "[aslr][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::aslr_bypass::AslrBypassCommand cmd;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}
