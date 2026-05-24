// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/gadget.hpp"
#include "abcpwn/commands/one_gadget.hpp"
#include "abcpwn/commands/rop.hpp"
#include "abcpwn/commands/rop_search.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

} // namespace

TEST_CASE("find_gadgets discovers a simple ret-only chain", "[rop][gadget]") {
    using namespace abcpwn::commands::rop;
    using abcpwn::arch::Arch;

    // pop rdi ; ret    -> 5f c3
    // pop rsi ; ret    -> 5e c3
    // ret              -> c3
    // syscall          -> 0f 05  (not a ret terminator; ignored)
    ExecutableSection sec;
    sec.name = ".text";
    sec.virtual_address = 0x400000;
    sec.bytes = {
        0x5f,
        0xc3, // 0x400000: pop rdi ; ret
        0x5e,
        0xc3, // 0x400002: pop rsi ; ret
        0x0f,
        0x05, // 0x400004: syscall (terminates differently)
        0xc3, // 0x400006: ret (lone)
    };

    GadgetSearchOptions opts;
    opts.arch = Arch::X86_64;
    opts.terminator = Terminator::Ret;
    opts.max_depth = 4;

    auto r = find_gadgets(std::span<const ExecutableSection>(&sec, 1), opts);
    REQUIRE(r);
    // Expect at least the three unique gadget texts:
    //   "pop rdi ; ret", "pop rsi ; ret", "ret"
    bool has_pop_rdi = false;
    bool has_pop_rsi = false;
    bool has_ret = false;
    for (const auto& g : *r) {
        if (g.text == "pop rdi ; ret")
            has_pop_rdi = true;
        if (g.text == "pop rsi ; ret")
            has_pop_rsi = true;
        if (g.text == "ret")
            has_ret = true;
    }
    REQUIRE(has_pop_rdi);
    REQUIRE(has_pop_rsi);
    REQUIRE(has_ret);
}

TEST_CASE("find_gadgets respects bad-chars filter", "[rop][gadget]") {
    using namespace abcpwn::commands::rop;
    using abcpwn::arch::Arch;

    ExecutableSection sec;
    sec.virtual_address = 0;
    // pop rax ; ret  -> 58 c3
    // pop rdi ; ret  -> 5f c3
    sec.bytes = {0x58, 0xc3, 0x5f, 0xc3};

    GadgetSearchOptions opts;
    opts.arch = Arch::X86_64;
    opts.terminator = Terminator::Ret;
    opts.max_depth = 2;
    opts.bad_chars = {0x58}; // exclude any gadget byte == 0x58

    auto r = find_gadgets(std::span<const ExecutableSection>(&sec, 1), opts);
    REQUIRE(r);
    // pop rax ; ret should be filtered; pop rdi ; ret survives
    bool has_pop_rax = false;
    bool has_pop_rdi = false;
    for (const auto& g : *r) {
        if (g.text == "pop rax ; ret")
            has_pop_rax = true;
        if (g.text == "pop rdi ; ret")
            has_pop_rdi = true;
    }
    REQUIRE_FALSE(has_pop_rax);
    REQUIRE(has_pop_rdi);
}

TEST_CASE("find_gadgets results sort ascending by address", "[rop][gadget]") {
    using namespace abcpwn::commands::rop;
    using abcpwn::arch::Arch;

    ExecutableSection sec;
    sec.virtual_address = 0x1000;
    sec.bytes = {
        0x5e,
        0xc3, // 0x1000: pop rsi ; ret
        0x5f,
        0xc3, // 0x1002: pop rdi ; ret
        0x58,
        0xc3, // 0x1004: pop rax ; ret
    };
    GadgetSearchOptions opts;
    opts.arch = Arch::X86_64;
    opts.terminator = Terminator::Ret;
    opts.max_depth = 2;
    auto r = find_gadgets(std::span<const ExecutableSection>(&sec, 1), opts);
    REQUIRE(r);
    REQUIRE(std::is_sorted(r->begin(), r->end(), [](const Gadget& a, const Gadget& b) {
        return a.address < b.address;
    }));
}

TEST_CASE("find_gadgets dedups by text, keeps lowest-VA address", "[rop][gadget]") {
    using namespace abcpwn::commands::rop;
    using abcpwn::arch::Arch;

    // Three lone `c3` bytes at different offsets all decode to "ret".
    // The dedup map must keep the lowest VA for that gadget text.
    ExecutableSection sec;
    sec.virtual_address = 0x1000;
    sec.bytes = {0xc3, 0xc3, 0xc3};
    GadgetSearchOptions opts;
    opts.arch = Arch::X86_64;
    opts.terminator = Terminator::Ret;
    opts.max_depth = 1;
    auto r = find_gadgets(std::span<const ExecutableSection>(&sec, 1), opts);
    REQUIRE(r);
    REQUIRE(r->size() == 1);
    REQUIRE((*r)[0].text == "ret");
    REQUIRE((*r)[0].address == 0x1000);
}

TEST_CASE("GadgetCommand finds gadgets in hello-hardened fixture", "[rop][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Never;
    abcpwn::commands::GadgetCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.depth = 4;
    cmd.no_progress = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    // Glibc-linked ELFs always have at least a "ret" gadget reachable
    // somewhere in .text / .plt.
    REQUIRE_FALSE(r->raw_lines.empty());
    bool any_ret = false;
    for (const auto& line : r->raw_lines) {
        if (line.find("ret") != std::string::npos) {
            any_ret = true;
            break;
        }
    }
    REQUIRE(any_ret);
}

TEST_CASE("GadgetCommand surfaces a truncation warning when --max-results is hit",
          "[rop][command][gadget][truncation]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Never;
    abcpwn::commands::GadgetCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.depth = 4;
    cmd.terminator = "all"; // widen so even a tiny binary produces > 1 gadget
    cmd.max_results = 1;    // force truncation on the first unique gadget
    cmd.no_progress = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->summary.has_value());
    REQUIRE(r->summary->find("truncated") != std::string::npos);
    bool saw_warning = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.severity == abcpwn::core::Severity::Medium
                && f.title.find("truncated") != std::string::npos) {
                saw_warning = true;
            }
        }
    }
    REQUIRE(saw_warning);
}

TEST_CASE("GadgetCommand rejects --max-results=0", "[rop][command][gadget]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::GadgetCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.max_results = 0;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

TEST_CASE("RopCommand without strategy is a usage error", "[rop][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::RopCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

TEST_CASE("OneGadgetCommand returns command result (may be empty)", "[rop][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::OneGadgetCommand cmd;
    cmd.libc = fixture("hello-hardened").string();
    auto r = cmd.run(ctx);
    REQUIRE(r); // never errors on a valid ELF
    REQUIRE_FALSE(r->sections.empty());
    // hello-hardened has no embedded /bin/sh string -- we expect the
    // "no /bin/sh string" finding.
    bool saw_no_binsh = false;
    for (const auto& f : r->sections[0].findings) {
        if (f.title.find("no /bin/sh") != std::string::npos)
            saw_no_binsh = true;
    }
    REQUIRE(saw_no_binsh);
}
