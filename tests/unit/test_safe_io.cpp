// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstddef>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/core/safe_io.hpp"

namespace {

std::filesystem::path make_tmp_dir() {
    auto base = std::filesystem::temp_directory_path() / "abcpwn-test";
    std::filesystem::create_directories(base);
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    auto dir = base / ("safeio-" + std::to_string(rng()));
    std::filesystem::create_directories(dir);
    return dir;
}

} // namespace

TEST_CASE("read_file returns the exact bytes", "[safe_io]") {
    using abcpwn::core::safe_io::read_file;

    const auto dir = make_tmp_dir();
    const auto p = dir / "hello.bin";
    {
        std::ofstream out(p, std::ios::binary);
        constexpr char payload[] = "hello\x00world";
        out.write(payload, sizeof payload - 1);
    }
    auto r = read_file(p);
    REQUIRE(r);
    REQUIRE(r->size() == 11);
    REQUIRE(static_cast<unsigned char>((*r)[5]) == 0);

    std::filesystem::remove_all(dir);
}

TEST_CASE("read_file refuses missing paths with NotFound", "[safe_io]") {
    using abcpwn::core::ErrorCode;
    using abcpwn::core::safe_io::read_file;

    const auto dir = make_tmp_dir();
    const auto p = dir / "does-not-exist";
    auto r = read_file(p);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::NotFound);
    std::filesystem::remove_all(dir);
}

TEST_CASE("read_file refuses directories", "[safe_io]") {
    using abcpwn::core::ErrorCode;
    using abcpwn::core::safe_io::read_file;

    const auto dir = make_tmp_dir();
    auto r = read_file(dir);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::InvalidInput);
    std::filesystem::remove_all(dir);
}

TEST_CASE("read_file enforces max_bytes", "[safe_io]") {
    using abcpwn::core::ErrorCode;
    using abcpwn::core::safe_io::read_file;
    using abcpwn::core::safe_io::ReadOptions;

    const auto dir = make_tmp_dir();
    const auto p = dir / "blob.bin";
    {
        std::ofstream out(p, std::ios::binary);
        out << std::string(1024, 'x');
    }
    ReadOptions opts;
    opts.max_bytes = 100;
    auto r = read_file(p, opts);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::SizeExceeded);
    std::filesystem::remove_all(dir);
}

TEST_CASE("write_text_file_atomic rewrites in place", "[safe_io]") {
    using abcpwn::core::safe_io::read_text_file;
    using abcpwn::core::safe_io::write_text_file_atomic;

    const auto dir = make_tmp_dir();
    const auto p = dir / "config.toml";
    auto w1 = write_text_file_atomic(p, "key = 1\n");
    REQUIRE(w1);
    auto r1 = read_text_file(p);
    REQUIRE(r1);
    REQUIRE(*r1 == "key = 1\n");

    auto w2 = write_text_file_atomic(p, "key = 2\n");
    REQUIRE(w2);
    auto r2 = read_text_file(p);
    REQUIRE(r2);
    REQUIRE(*r2 == "key = 2\n");

    std::filesystem::remove_all(dir);
}
