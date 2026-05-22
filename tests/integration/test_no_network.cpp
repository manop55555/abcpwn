// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// Security-critical: verify that the only commands authorized to
// touch the network (libc download, pwninit fetch) actually refuse
// to run without --allow-network. This pins one of the core project
// invariants: nothing reaches the wire by default.

#include "abcpwn/commands/libc.hpp"
#include "abcpwn/commands/pwninit.hpp"
#include "abcpwn/core/context.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("libc download requires ctx.allow_network = true",
          "[integration][security][no-network]")
{
    abcpwn::core::Context ctx;
    ctx.allow_network = false;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action     = "download";
    cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::NetworkDisabled);
    // The error must surface the gate so an operator inspecting the
    // failed run knows how to authorize: --allow-network.
    REQUIRE(r.error().message.find("allow-network") != std::string::npos);
}

TEST_CASE("libc download with allow_network=true still gated by compile flag",
          "[integration][security][no-network]")
{
    // When the build was produced without ABCPWN_WITH_NETWORK, the
    // command must surface FeatureDisabled even if the runtime gate
    // was opened. This is the belt-and-braces check that an
    // Apache-2.0 build never has network code linked in.
    if (abcpwn::commands::libc::network_compiled_in()) {
        SKIP("network was compiled in; the compile-time gate path is "
             "not active here");
    }
    abcpwn::core::Context ctx;
    ctx.allow_network = true;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action     = "download";
    cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::FeatureDisabled);
}

TEST_CASE("pwninit on a directory without --allow-network does not download",
          "[integration][security][no-network]")
{
    // pwninit's plan output enumerates the steps it would execute.
    // Without --allow-network the libc-id / ld-fetch entries must
    // surface the gate, not the actual network call. This is the
    // user-visible signal that no fetch happened.
    abcpwn::core::Context ctx;
    ctx.allow_network = false;
    abcpwn::commands::pwninit::PwninitCommand cmd;
    cmd.directory = "/nonexistent-pwninit-workspace-for-test";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool saw_gate_note = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.detail.find("--allow-network") != std::string::npos
             || f.detail.find("not actually download") != std::string::npos)
            {
                saw_gate_note = true;
            }
        }
    }
    REQUIRE(saw_gate_note);
}
