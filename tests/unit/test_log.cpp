// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <filesystem>
#include <fstream>
#include <random>
#include <sstream>
#include <string>

#include <spdlog/logger.h>
#include <spdlog/spdlog.h>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/core/context.hpp"
#include "abcpwn/output/log.hpp"

namespace {

std::filesystem::path tmp_log_path() {
    auto base = std::filesystem::temp_directory_path() / "abcpwn-test";
    std::filesystem::create_directories(base);
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    return base / ("log-" + std::to_string(rng()) + ".log");
}

} // namespace

TEST_CASE("get_logger never returns null", "[log]") {
    auto l = abcpwn::output::get_logger();
    REQUIRE(l != nullptr);
}

TEST_CASE("setup_logging with log_file writes to that file", "[log]") {
    const auto p = tmp_log_path();
    abcpwn::core::Context ctx;
    ctx.log_file = p.string();
    ctx.verbosity = 1; // debug
    abcpwn::output::setup_logging(ctx);

    auto l = abcpwn::output::get_logger();
    l->info("hello-from-log-test");
    l->flush();

    REQUIRE(std::filesystem::exists(p));
    std::ifstream in(p);
    std::stringstream ss;
    ss << in.rdbuf();
    REQUIRE(ss.str().find("hello-from-log-test") != std::string::npos);

    REQUIRE(abcpwn::output::last_log_path_for_testing() == p.string());
    std::filesystem::remove(p);
}

TEST_CASE("setup_logging is idempotent", "[log]") {
    abcpwn::core::Context ctx;
    ctx.verbosity = 0;
    abcpwn::output::setup_logging(ctx);
    abcpwn::output::setup_logging(ctx);
    abcpwn::output::setup_logging(ctx);
    auto l = abcpwn::output::get_logger();
    REQUIRE(l != nullptr);
}

TEST_CASE("verbosity controls level", "[log]") {
    abcpwn::core::Context ctx;
    ctx.verbosity = 2;
    abcpwn::output::setup_logging(ctx);
    auto l = abcpwn::output::get_logger();
    REQUIRE(l->level() == spdlog::level::trace);

    ctx.verbosity = -1;
    abcpwn::output::setup_logging(ctx);
    l = abcpwn::output::get_logger();
    REQUIRE(l->level() == spdlog::level::warn);
}
