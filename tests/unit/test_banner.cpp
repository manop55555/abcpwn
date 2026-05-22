// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/output/banner.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace {

std::string read_snapshot(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    REQUIRE(in.good());
    std::ostringstream oss;
    oss << in.rdbuf();
    return std::move(oss).str();
}

constexpr const char* snapshot_env = "ABCPWN_BANNER_SNAPSHOT";

}  // namespace

TEST_CASE("banner is byte-identical to the snapshot", "[banner][snapshot]") {
    const char* path = std::getenv(snapshot_env);
    REQUIRE(path != nullptr);

    const std::string expected = read_snapshot(path);
    const std::string_view actual = abcpwn::output::banner_text();

    // Compare sizes first so a mismatch produces a useful diff.
    REQUIRE(actual.size() == expected.size());
    REQUIRE(std::string(actual) == expected);
}

TEST_CASE("banner has the expected number of lines", "[banner]") {
    const std::string_view text = abcpwn::output::banner_text();

    std::size_t lines = 0;
    for (const char c : text) {
        if (c == '\n') {
            ++lines;
        }
    }
    REQUIRE(lines == 13);
}

TEST_CASE("compact header references the project version", "[banner]") {
    REQUIRE(abcpwn::output::compact_header().find("v0.1.0") != std::string_view::npos);
    REQUIRE(abcpwn::output::compact_header().find("abcpwn") != std::string_view::npos);
}

TEST_CASE("print_banner without color emits raw banner bytes", "[banner]") {
    std::ostringstream oss;
    abcpwn::output::print_banner(oss, /*color=*/false);
    REQUIRE(oss.str() == abcpwn::output::banner_text());
}

TEST_CASE("print_banner with color wraps banner in ANSI codes", "[banner]") {
    std::ostringstream oss;
    abcpwn::output::print_banner(oss, /*color=*/true);
    const std::string out = oss.str();
    REQUIRE(out.starts_with("\x1b[2m"));
    REQUIRE(out.ends_with("\x1b[0m"));
}
