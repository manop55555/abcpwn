// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/formats/binary_loader.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixtures_dir() {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries";
}

std::filesystem::path tmp_file(std::string_view name) {
    auto base = std::filesystem::temp_directory_path() / "abcpwn-test";
    std::filesystem::create_directories(base);
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    return base / (std::string(name) + "-" + std::to_string(rng()));
}

} // namespace

TEST_CASE("sniff_format recognizes ELF, PE, and Mach-O magic", "[binary_loader]") {
    using abcpwn::formats::BinaryFormat;
    using abcpwn::formats::sniff_format;
    REQUIRE(sniff_format(std::string_view("\x7f"
                                          "ELF__",
                                          6))
            == BinaryFormat::Elf);
    REQUIRE(sniff_format("MZ____") == BinaryFormat::Pe);
    REQUIRE(sniff_format(std::string_view("\xce\xfa\xed\xfe", 4)) == BinaryFormat::MachO);
    REQUIRE(sniff_format(std::string_view("\xcf\xfa\xed\xfe", 4)) == BinaryFormat::MachO);
    REQUIRE(sniff_format("random") == BinaryFormat::Unknown);
}

TEST_CASE("load on a missing file returns NotFound", "[binary_loader]") {
    using abcpwn::core::ErrorCode;
    using abcpwn::formats::load;
    auto r = load("/no/such/path/abcpwn/missing");
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::NotFound);
}

TEST_CASE("load refuses a tiny file (corrupted)", "[binary_loader]") {
    using abcpwn::core::ErrorCode;
    using abcpwn::formats::load;
    const auto p = tmp_file("tiny");
    {
        std::ofstream out(p, std::ios::binary);
        out << "ab";
    }
    auto r = load(p);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::Corrupted);
    std::filesystem::remove(p);
}

TEST_CASE("load on a hardened ELF surfaces format, arch, entry, and danger",
          "[binary_loader][fixture]") {
    const auto fdir = fixtures_dir();
    if (fdir.empty() || !std::filesystem::exists(fdir / "hello-hardened")) {
        SKIP("hello-hardened fixture not present (run tests/fixtures/generate_fixtures.sh)");
    }
    auto r = abcpwn::formats::load(fdir / "hello-hardened");
    REQUIRE(r);
    const auto& info = r->info();

    REQUIRE(info.format == abcpwn::formats::BinaryFormat::Elf);
    REQUIRE(info.bits == abcpwn::formats::BinaryBits::Bits64);
    REQUIRE(info.endian == abcpwn::formats::Endian::Little);
    REQUIRE(info.arch == "x86_64");
    REQUIRE(info.entry_point != 0);
    REQUIRE(info.file_size > 0);
    REQUIRE(info.mitigations.pie);
    REQUIRE(info.mitigations.nx);
    // gets is in the dangerous list and we linked against it; strcpy too.
    bool has_dangerous = false;
    for (const auto& d : info.dangerous_functions) {
        if (d == "gets" || d == "strcpy") {
            has_dangerous = true;
        }
    }
    REQUIRE(has_dangerous);
}

TEST_CASE("load on a stripped ELF reports stripped=true", "[binary_loader][fixture]") {
    const auto fdir = fixtures_dir();
    if (fdir.empty() || !std::filesystem::exists(fdir / "hello-stripped")) {
        SKIP("hello-stripped fixture not present");
    }
    auto r = abcpwn::formats::load(fdir / "hello-stripped");
    REQUIRE(r);
    REQUIRE(r->info().mitigations.stripped);
}

TEST_CASE("load respects max_bytes", "[binary_loader]") {
    using abcpwn::core::ErrorCode;
    using abcpwn::formats::load;
    using abcpwn::formats::LoadOptions;
    const auto fdir = fixtures_dir();
    if (fdir.empty() || !std::filesystem::exists(fdir / "hello-hardened")) {
        SKIP("hello-hardened fixture not present");
    }
    LoadOptions opts;
    opts.max_bytes = 1024; // smaller than the fixture
    auto r = load(fdir / "hello-hardened", opts);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::SizeExceeded);
}
