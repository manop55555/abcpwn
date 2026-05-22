// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <string>
#include <vector>

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/libc.hpp"
#include "abcpwn/core/context.hpp"

TEST_CASE("libc id with two offsets against in-binary table", "[!benchmark][libc]") {
    abcpwn::core::Context ctx;

    // Same fingerprint pair as the test_ret2libc_flow integration
    // test (glibc 2.34 system + execve low-12 bits).
    const std::vector<std::string> pairs = {"system:0x550", "execve:0xd30"};

    BENCHMARK("libc id / 2 offsets") {
        abcpwn::commands::libc::LibcCommand cmd;
        cmd.action = "id";
        cmd.offset_pairs = pairs;
        auto r = cmd.run(ctx);
        return r.has_value();
    };
}

TEST_CASE("libc offsets pulls every entry for a known id", "[!benchmark][libc]") {
    abcpwn::core::Context ctx;

    BENCHMARK("libc offsets / glibc 2.34") {
        abcpwn::commands::libc::LibcCommand cmd;
        cmd.action = "offsets";
        cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
        auto r = cmd.run(ctx);
        return r ? r->sections[0].findings.size() : 0U;
    };
}
