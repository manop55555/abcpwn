// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/got.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

} // namespace

TEST_CASE("GotCommand lists GOT entries from hello-hardened", "[got][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::got::GotCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    bool has_strcpy = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "strcpy")
                has_strcpy = true;
        }
    }
    REQUIRE(has_strcpy); // fixture imports strcpy
}

TEST_CASE("GotCommand --symbol filters to one entry", "[got][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::got::GotCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.symbol_filter = "strcpy";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    int matches = 0;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "strcpy")
                ++matches;
        }
    }
    REQUIRE(matches == 1);
}

TEST_CASE("GotCommand --overwrite emits a write primitive", "[got][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::got::GotCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.overwrite = "strcpy=0xdeadbeef";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool saw_primitive = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "primitive" && f.detail.find("0xdeadbeef") != std::string::npos) {
                saw_primitive = true;
            }
        }
    }
    REQUIRE(saw_primitive);
}

TEST_CASE("GotCommand --overwrite rejects missing equals", "[got][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::got::GotCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.overwrite = "strcpy_no_equals";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

TEST_CASE("GotCommand --overwrite rejects unknown symbol", "[got][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::got::GotCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.overwrite = "no_such_symbol=0x123";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::NotFound);
}
