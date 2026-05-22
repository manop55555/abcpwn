// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/core/progress.hpp"
#include "abcpwn/core/signal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <sstream>
#include <thread>

using namespace std::chrono_literals;

TEST_CASE("progress tracks counts and totals", "[progress]") {
    abcpwn::core::ProgressReporter::Options opts;
    opts.label    = "test";
    opts.total    = 10;
    opts.use_stderr = false;
    abcpwn::core::ProgressReporter r(std::move(opts));
    r.advance(3);
    REQUIRE(r.current() == 3);
    REQUIRE(r.total() == 10);
    r.advance(7);
    REQUIRE(r.current() == 10);
    r.finish();
}

TEST_CASE("progress fires on_tick callback", "[progress]") {
    std::atomic<std::uint64_t> last_cur{0};
    abcpwn::core::ProgressReporter::Options opts;
    opts.total      = 0;  // indeterminate
    opts.use_stderr = false;
    opts.on_tick = [&](std::uint64_t cur, std::uint64_t /*total*/) {
        last_cur.store(cur);
    };
    abcpwn::core::ProgressReporter r(std::move(opts));
    r.advance();
    r.advance(4);
    r.finish();
    REQUIRE(last_cur.load() == 5);
}

TEST_CASE("signal flag stays set until reset", "[signal]") {
    using namespace abcpwn::core::signal;
    reset_for_testing();
    REQUIRE_FALSE(cancellation_requested());
    request_cancellation();
    REQUIRE(cancellation_requested());
    REQUIRE(cancellation_requested());  // still set
    reset_for_testing();
    REQUIRE_FALSE(cancellation_requested());
}

TEST_CASE("install_handlers is idempotent", "[signal]") {
    abcpwn::core::signal::install_handlers();
    abcpwn::core::signal::install_handlers();
    abcpwn::core::signal::install_handlers();
    SUCCEED("no crash");
}
