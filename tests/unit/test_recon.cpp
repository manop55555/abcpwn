// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/hash.hpp"
#include "abcpwn/commands/info.hpp"
#include "abcpwn/commands/search.hpp"
#include "abcpwn/commands/strings.hpp"
#include "abcpwn/commands/syms.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

}  // namespace

TEST_CASE("InfoCommand on hardened ELF surfaces sections", "[recon][info]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::InfoCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->sections.size() >= 3);
    bool found_pie = false;
    for (const auto& s : r->sections) {
        if (s.title == "Mitigations") {
            for (const auto& f : s.findings) {
                if (f.title == "PIE" && f.detail == "yes") found_pie = true;
            }
        }
    }
    REQUIRE(found_pie);
}

TEST_CASE("SymsCommand --dangerous lists gets/strcpy", "[recon][syms]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::SymsCommand cmd;
    cmd.target         = fixture("hello-hardened").string();
    cmd.dangerous_only = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool any_dangerous = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "gets" || f.title == "strcpy") {
                any_dangerous = true;
            }
        }
    }
    REQUIRE(any_dangerous);
}

TEST_CASE("extract_ascii_strings finds the ELF magic and a known string", "[recon][strings]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::StringsCommand cmd;
    cmd.target     = fixture("hello-hardened").string();
    cmd.min_length = 6;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool found_libc = false;
    for (const auto& l : r->raw_lines) {
        if (l.find("libc") != std::string::npos) found_libc = true;
    }
    REQUIRE(found_libc);
}

TEST_CASE("SearchCommand finds the ELF magic with --hex", "[recon][search]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::SearchCommand cmd;
    cmd.target  = fixture("hello-hardened").string();
    cmd.pattern = "7f454c46";
    cmd.as_hex  = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->raw_lines.empty());
    REQUIRE(r->raw_lines[0].find("0x0 ") == 0);
}

TEST_CASE("sha256_hex matches known test vector", "[recon][hash]") {
    using abcpwn::commands::sha256_hex;
    // Empty input
    REQUIRE(sha256_hex(std::span<const std::uint8_t>{}) ==
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    const std::vector<std::uint8_t> abc{'a', 'b', 'c'};
    REQUIRE(sha256_hex(abc) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST_CASE("HashCommand hashes a fixture file", "[recon][hash]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::HashCommand cmd;
    cmd.targets = {fixture("hello-hardened").string()};
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0].size() >= 64);  // hex digest + path
}
