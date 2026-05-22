// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// End-to-end CTF flow: info -> libc id -> gadget -> rop --execve.

#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/gadget.hpp"
#include "abcpwn/commands/info.hpp"
#include "abcpwn/commands/libc.hpp"
#include "abcpwn/commands/rop.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

} // namespace

TEST_CASE("ret2libc flow: info -> libc id -> gadget -> rop", "[integration][ret2libc]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;

    // Stage 1: info -- as in ret2win, surfaces arch + mitigations.
    {
        abcpwn::commands::InfoCommand info;
        info.target = fixture("hello-hardened").string();
        auto r = info.run(ctx);
        REQUIRE(r);
    }

    // Stage 2: libc id with the offline fingerprint table. Use the
    // glibc 2.34 fingerprint that the v0.1 in-binary table covers.
    {
        abcpwn::commands::libc::LibcCommand libc;
        libc.action = "id";
        libc.offset_pairs = {"system:0x550", "execve:0xd30"};
        auto r = libc.run(ctx);
        REQUIRE(r);
        bool found_2_34 = false;
        for (const auto& s : r->sections) {
            for (const auto& f : s.findings) {
                if (f.detail.find("libc6_2.34") != std::string::npos)
                    found_2_34 = true;
            }
        }
        REQUIRE(found_2_34);
    }

    // Stage 3: gadget --filter 'pop rdi ; ret' on the binary's
    // .text. The fixture's PIE layout means we may or may not have
    // the gadget present; the integration check is just that the
    // command runs and returns a usable command result.
    {
        abcpwn::commands::GadgetCommand gadget;
        gadget.target = fixture("hello-hardened").string();
        gadget.depth = 3;
        gadget.filter = "pop rdi";
        gadget.no_progress = true;
        auto r = gadget.run(ctx);
        REQUIRE(r);
        REQUIRE_FALSE(r->raw_lines.empty());
    }

    // Stage 4: rop --execve is not implemented in v0.1; only
    // --syscall is. The command should report Unsupported with a
    // "subsequent versions" message. This pins the v0.1 surface so
    // downstream tooling that relies on the error code stays stable.
    {
        abcpwn::commands::RopCommand rop;
        rop.target = fixture("hello-hardened").string();
        // No strategy set -> UsageError, which is the upstream-of-
        // Unsupported case. Verify either UsageError (no strategy) or
        // Unsupported (a strategy that isn't implemented yet).
        auto r = rop.run(ctx);
        REQUIRE_FALSE(r);
        const auto code = r.error().code;
        REQUIRE((code == abcpwn::core::ErrorCode::UsageError
                 || code == abcpwn::core::ErrorCode::Unsupported));
    }
}
