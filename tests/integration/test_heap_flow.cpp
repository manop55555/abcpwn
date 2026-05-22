// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// End-to-end heap flow: pick a technique, ask the compatibility
// table for its status on the user's libc, follow the safe-link
// encode/decode hint when targeting modern glibc. Covers the same
// shape as a CTF player working backwards from a target libc to a
// viable technique.

#include <cstdint>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/heap.hpp"
#include "abcpwn/commands/safe_link.hpp"
#include "abcpwn/core/context.hpp"

TEST_CASE("heap flow: technique compat -> safe-link encode", "[integration][heap]") {
    abcpwn::core::Context ctx;

    // Stage 1: ask "does tcache-poison work on 2.34?". Expected:
    // MITIGATED (safe-linking landed in 2.32, makes the naive poison
    // require a heap leak).
    {
        abcpwn::commands::heap::HeapCommand cmd;
        cmd.technique_str = "tcache-poison";
        cmd.libc_version_str = "2.34";
        auto r = cmd.run(ctx);
        REQUIRE(r);
        bool seen_mitigated = false;
        for (const auto& s : r->sections) {
            for (const auto& f : s.findings) {
                if (f.title == "status" && f.detail == "MITIGATED")
                    seen_mitigated = true;
            }
        }
        REQUIRE(seen_mitigated);
    }

    // Stage 2: the player needs to obfuscate their fd write with
    // glibc safe-linking. safe_link_encode produces a value that
    // safe_link_decode at the same pos recovers exactly.
    constexpr std::uint64_t target_chunk = 0x55aabbccdd001000ULL;
    constexpr std::uint64_t fd_pos = 0x55aabbccdd002400ULL;
    const auto encoded = abcpwn::commands::safe_link::safe_link_encode(target_chunk, fd_pos);
    REQUIRE(encoded != target_chunk);
    REQUIRE(abcpwn::commands::safe_link::safe_link_decode(encoded, fd_pos) == target_chunk);

    // Stage 3: same technique on 2.27 should be WORKS (safe-linking
    // not yet landed). This pins the compatibility direction.
    {
        abcpwn::commands::heap::HeapCommand cmd;
        cmd.technique_str = "tcache-poison";
        cmd.libc_version_str = "2.27";
        auto r = cmd.run(ctx);
        REQUIRE(r);
        bool seen_works = false;
        for (const auto& s : r->sections) {
            for (const auto& f : s.findings) {
                if (f.title == "status" && f.detail == "WORKS")
                    seen_works = true;
            }
        }
        REQUIRE(seen_works);
    }

    // Stage 4: --all-libcs walks every era so the player sees the
    // direction of the compat curve at a glance.
    {
        abcpwn::commands::heap::HeapCommand cmd;
        cmd.technique_str = "house-of-force";
        cmd.all_libcs = true;
        auto r = cmd.run(ctx);
        REQUIRE(r);
        REQUIRE_FALSE(r->sections.empty());
        REQUIRE(r->sections[0].findings.size() == 5);
    }
}
