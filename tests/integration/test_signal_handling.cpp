// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// SIGINT cancellation contract: a long-running command must observe
// signal::cancellation_requested and exit cleanly with the Cancelled
// ErrorCode. We test the contract end-to-end by:
//   1. installing handlers via the public API
//   2. firing request_cancellation() before invoking the gadget
//      finder (which polls the flag every 0x100 offsets)
//   3. verifying the result is the Cancelled error
//
// The same path is what a real SIGINT exercises -- the handler just
// sets the same flag. Testing the post-flag-set path is sufficient;
// going through the kernel adds flakiness without coverage gain.

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/rop_search.hpp"
#include "abcpwn/core/result.hpp"
#include "abcpwn/core/signal.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <span>
#include <vector>

TEST_CASE("signal handlers install idempotently", "[integration][signal]") {
    abcpwn::core::signal::install_handlers();
    abcpwn::core::signal::install_handlers();
    REQUIRE_FALSE(abcpwn::core::signal::cancellation_requested());
}

TEST_CASE("request_cancellation flag is sticky", "[integration][signal]") {
    abcpwn::core::signal::reset_for_testing();
    REQUIRE_FALSE(abcpwn::core::signal::cancellation_requested());
    abcpwn::core::signal::request_cancellation();
    REQUIRE(abcpwn::core::signal::cancellation_requested());
    // Re-check after a barrier to confirm the flag is sticky.
    REQUIRE(abcpwn::core::signal::cancellation_requested());
    abcpwn::core::signal::reset_for_testing();
    REQUIRE_FALSE(abcpwn::core::signal::cancellation_requested());
}

TEST_CASE("gadget finder honors cancellation flag", "[integration][signal]") {
    // Build a section large enough that the finder hits the
    // cancellation poll point (every 0x100 offsets) at least once.
    std::vector<std::uint8_t> bytes(0x800, 0x90);  // 2048 NOPs
    bytes.back() = 0xc3;                            // trailing ret
    abcpwn::commands::rop::ExecutableSection sec;
    sec.name            = ".text";
    sec.virtual_address = 0x400000;
    sec.bytes           = bytes;

    abcpwn::commands::rop::GadgetSearchOptions opts;
    opts.arch       = abcpwn::arch::Arch::X86_64;
    opts.terminator = abcpwn::commands::rop::Terminator::Ret;
    opts.max_depth  = 4;

    // Pre-fire cancellation. The finder must observe it on its next
    // poll point and surface ErrorCode::Cancelled.
    abcpwn::core::signal::reset_for_testing();
    abcpwn::core::signal::request_cancellation();

    auto r = abcpwn::commands::rop::find_gadgets(
        std::span<const abcpwn::commands::rop::ExecutableSection>(&sec, 1),
        opts);

    abcpwn::core::signal::reset_for_testing();  // clean up for other tests

    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::Cancelled);
}
