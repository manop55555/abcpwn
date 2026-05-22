// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/bench_paths.hpp"
#include "abcpwn/commands/gadget.hpp"
#include "abcpwn/commands/rop_search.hpp"
#include "abcpwn/core/context.hpp"

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

TEST_CASE("gadget command on hello-hardened fixture", "[!benchmark][gadget]") {
    const auto fix = std::filesystem::path(abcpwn::bench_paths::fixtures_dir)
                   / "binaries" / "hello-hardened";
    if (!std::filesystem::exists(fix)) {
        SKIP("hello-hardened fixture missing");
    }
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Never;

    BENCHMARK("gadget / hello-hardened / depth=4") {
        abcpwn::commands::GadgetCommand cmd;
        cmd.target      = fix.string();
        cmd.depth       = 4;
        cmd.no_progress = true;
        auto r = cmd.run(ctx);
        return r ? r->raw_lines.size() : 0U;
    };
}

TEST_CASE("gadget find on a 4 KiB synthetic section", "[!benchmark][gadget]") {
    // 4096 bytes of repeating "pop rdi ; ret" -> ~2000 gadgets after dedup.
    std::vector<std::uint8_t> bytes(4096, 0x90);
    for (std::size_t i = 0; i + 1 < bytes.size(); i += 4) {
        bytes[i]     = 0x5f;   // pop rdi
        bytes[i + 1] = 0xc3;   // ret
    }
    abcpwn::commands::rop::ExecutableSection sec;
    sec.name            = ".text";
    sec.virtual_address = 0x400000;
    sec.bytes           = bytes;

    abcpwn::commands::rop::GadgetSearchOptions opts;
    opts.arch       = abcpwn::arch::Arch::X86_64;
    opts.terminator = abcpwn::commands::rop::Terminator::Ret;
    opts.max_depth  = 3;

    BENCHMARK("find_gadgets / 4 KiB synthetic") {
        auto r = abcpwn::commands::rop::find_gadgets(
            std::span<const abcpwn::commands::rop::ExecutableSection>(&sec, 1),
            opts);
        return r ? r->size() : 0U;
    };
}
