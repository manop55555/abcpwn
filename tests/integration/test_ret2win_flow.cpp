// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// End-to-end CTF flow: info -> syms -> rop -> cyclic. Runs each
// command against the hello-hardened fixture and threads results
// from one stage into the next, the way a CTF player would.

#include <filesystem>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/cyclic.hpp"
#include "abcpwn/commands/info.hpp"
#include "abcpwn/commands/rop.hpp"
#include "abcpwn/commands/syms.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

} // namespace

TEST_CASE("ret2win flow chains info -> syms -> rop -> cyclic", "[integration][ret2win]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Never;

    // Stage 1: info reports the binary's mitigations and dangerous funcs.
    std::string arch;
    bool info_has_pie = false;
    {
        abcpwn::commands::InfoCommand info;
        info.target = fixture("hello-hardened").string();
        auto r = info.run(ctx);
        REQUIRE(r);
        for (const auto& s : r->sections) {
            for (const auto& f : s.findings) {
                if (f.title == "arch")
                    arch = f.detail;
                if (f.title == "PIE" && f.detail == "yes")
                    info_has_pie = true;
            }
        }
    }
    REQUIRE(arch == "x86_64");
    REQUIRE(info_has_pie);

    // Stage 2: syms --dangerous surfaces the gets/strcpy imports that
    // make the ret2win path viable for this fixture.
    {
        abcpwn::commands::SymsCommand syms;
        syms.target = fixture("hello-hardened").string();
        syms.dangerous_only = true;
        auto r = syms.run(ctx);
        REQUIRE(r);
        bool any_dangerous = false;
        for (const auto& s : r->sections) {
            for (const auto& f : s.findings) {
                if (f.title == "gets" || f.title == "strcpy")
                    any_dangerous = true;
            }
        }
        REQUIRE(any_dangerous);
    }

    // Stage 3: rop --syscall requires gadget classes the C fixture
    // does not contain (no pop rax). The flow returns NotFound with a
    // descriptive list of missing gadgets -- exactly the feedback a
    // CTF player needs to switch strategies.
    {
        abcpwn::commands::RopCommand rop;
        rop.target = fixture("hello-hardened").string();
        rop.syscall_number = 59;
        rop.syscall_args = {0x600000};
        auto r = rop.run(ctx);
        // Either the fixture has enough gadgets -> Ok, or it does not
        // -> NotFound with "missing gadgets" message. Both are valid
        // ret2win flow outcomes; the integration check is that the
        // command runs and the response is shaped correctly.
        if (!r) {
            REQUIRE(r.error().code == abcpwn::core::ErrorCode::NotFound);
            REQUIRE(r.error().message.find("missing") != std::string::npos);
        } else {
            REQUIRE_FALSE(r->sections.empty());
        }
    }

    // Stage 4: cyclic_find recovers the offset of a known subseq from
    // the generated pwntools-compatible sequence -- the same op a
    // CTF player uses after triggering a crash with `abcpwn cyclic
    // 128` and reading RIP from gdb.
    {
        const auto seq = abcpwn::commands::cyclic_generate(120);
        const std::string probe = seq.substr(64, 4);
        auto off = abcpwn::commands::cyclic_find(probe);
        REQUIRE(off.has_value());
        REQUIRE(*off == 64);
    }
}
