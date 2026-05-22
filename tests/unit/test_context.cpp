// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/core/config.hpp"
#include "abcpwn/core/context.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("default context has safe defaults", "[context]") {
    abcpwn::core::Context ctx;
    REQUIRE(ctx.format == abcpwn::core::OutputFormat::Pretty);
    REQUIRE(ctx.color == abcpwn::core::ColorMode::Auto);
    REQUIRE_FALSE(ctx.allow_network);
    REQUIRE_FALSE(ctx.no_banner);
    REQUIRE(ctx.verbosity == 0);
    REQUIRE(ctx.limits.max_file_bytes >= 1024);
    REQUIRE_FALSE(ctx.quiet());
    REQUIRE_FALSE(ctx.debug());
}

TEST_CASE("verbosity helpers", "[context]") {
    abcpwn::core::Context ctx;
    ctx.verbosity = -1;
    REQUIRE(ctx.quiet());
    ctx.verbosity = 2;
    REQUIRE(ctx.debug());
}

TEST_CASE("config parses [section] key = value pairs", "[context][config]") {
    auto r = abcpwn::core::config::parse(
        "[output]\n"
        "color = \"always\"\n"
        "format = \"json\"\n"
        "allow_network = true\n"
        "[limits]\n"
        "max_threads = 4\n"
        "max_runtime_seconds = 1800\n");
    REQUIRE(r);

    abcpwn::core::Context ctx;
    apply_to_context(*r, ctx);

    REQUIRE(ctx.format == abcpwn::core::OutputFormat::Json);
    REQUIRE(ctx.color == abcpwn::core::ColorMode::Always);
    REQUIRE(ctx.allow_network);
    REQUIRE(ctx.limits.max_threads == 4);
    REQUIRE(ctx.limits.max_runtime.count() == 1800);
}

TEST_CASE("config supports hex and negative integers", "[config]") {
    auto r = abcpwn::core::config::parse(
        "[demo]\n"
        "hex = 0xCAFE\n"
        "neg = -42\n"
        "pos = +17\n");
    REQUIRE(r);
    REQUIRE(*r->get_int("demo", "hex") == 0xCAFE);
    REQUIRE(*r->get_int("demo", "neg") == -42);
    REQUIRE(*r->get_int("demo", "pos") == 17);
}

TEST_CASE("config handles comments and blank lines", "[config]") {
    auto r = abcpwn::core::config::parse(
        "# top of file\n"
        "\n"
        "[a]\n"
        "k = \"v\"  # inline\n"
        "# trailing comment\n");
    REQUIRE(r);
    REQUIRE(*r->get_string("a", "k") == "v");
}

TEST_CASE("config rejects malformed input", "[config]") {
    REQUIRE_FALSE(abcpwn::core::config::parse("key without equals\n"));
    REQUIRE_FALSE(abcpwn::core::config::parse("[unterminated\n"));
    REQUIRE_FALSE(abcpwn::core::config::parse("key = \"unterminated\n"));
}
