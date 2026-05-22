// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/bench_paths.hpp"
#include "abcpwn/commands/info.hpp"
#include "abcpwn/core/context.hpp"

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <string>

TEST_CASE("info command on hello-hardened fixture", "[!benchmark][info]") {
    const auto fix = std::filesystem::path(abcpwn::bench_paths::fixtures_dir)
                   / "binaries" / "hello-hardened";
    if (!std::filesystem::exists(fix)) {
        SKIP("hello-hardened fixture missing");
    }
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Never;

    BENCHMARK("info / hello-hardened") {
        abcpwn::commands::InfoCommand cmd;
        cmd.target = fix.string();
        auto r = cmd.run(ctx);
        return r.has_value();
    };
}
