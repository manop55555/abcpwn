// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <chrono>
#include <sstream>
#include <string>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"
#include "abcpwn/output/markers.hpp"
#include "abcpwn/output/pretty.hpp"

namespace {

abcpwn::core::Context never_color_ctx() {
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Never;
    ctx.format = abcpwn::core::OutputFormat::Pretty;
    return ctx;
}

abcpwn::core::Context always_color_ctx() {
    abcpwn::core::Context ctx;
    ctx.color = abcpwn::core::ColorMode::Always;
    ctx.format = abcpwn::core::OutputFormat::Pretty;
    return ctx;
}

} // namespace

TEST_CASE("pretty header lists tool name and tagline", "[pretty]") {
    auto ctx = never_color_ctx();
    abcpwn::output::PrettyPrinter pp(ctx);
    std::ostringstream oss;
    pp.print_command_header(oss);
    const std::string out = oss.str();
    REQUIRE(out.find("abcpwn v0.1.0") != std::string::npos);
    REQUIRE(out.find("binary exploitation toolkit") != std::string::npos);
    REQUIRE(out.find("\x1b[") == std::string::npos); // no ANSI without color
}

TEST_CASE("pretty section renders marker, title, detail, severity tag", "[pretty]") {
    auto ctx = never_color_ctx();
    abcpwn::output::PrettyPrinter pp(ctx);

    abcpwn::core::Section s;
    s.title = "Mitigations";
    s.findings.emplace_back(abcpwn::core::Severity::Info, "RELRO", "full");
    s.findings.emplace_back(abcpwn::core::Severity::High, "Fortify", "no");

    std::ostringstream oss;
    pp.print_command_header(oss);
    pp.print_section(oss, s);
    const std::string out = oss.str();

    REQUIRE(out.find("Mitigations") != std::string::npos);
    REQUIRE(out.find("[*] RELRO") != std::string::npos);
    REQUIRE(out.find("[-] Fortify") != std::string::npos);
    REQUIRE(out.find("[HIGH]") != std::string::npos);
    REQUIRE(out.find("[INFO]") == std::string::npos); // info severity tag suppressed
}

TEST_CASE("pretty respects --no-color via context", "[pretty]") {
    auto ctx = never_color_ctx();
    abcpwn::output::PrettyPrinter pp(ctx);
    abcpwn::core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "Stuff";
    sec.findings.emplace_back(abcpwn::core::Severity::High, "bad");

    std::ostringstream oss;
    pp.print_command_result(oss, res);
    REQUIRE(oss.str().find("\x1b[") == std::string::npos);
}

TEST_CASE("pretty emits ANSI codes when color forced on", "[pretty]") {
    auto ctx = always_color_ctx();
    abcpwn::output::PrettyPrinter pp(ctx);
    abcpwn::core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "Stuff";
    sec.findings.emplace_back(abcpwn::core::Severity::High, "bad");

    std::ostringstream oss;
    pp.print_command_header(oss);
    pp.print_command_result(oss, res);
    REQUIRE(oss.str().find("\x1b[") != std::string::npos);
}

TEST_CASE("pretty appends duration line", "[pretty]") {
    auto ctx = never_color_ctx();
    abcpwn::output::PrettyPrinter pp(ctx);
    abcpwn::core::CommandResult res;
    res.duration = std::chrono::milliseconds{42};

    std::ostringstream oss;
    pp.print_command_result(oss, res);
    REQUIRE(oss.str().find("(42 ms)") != std::string::npos);
}

TEST_CASE("should_color is false when format is json", "[pretty]") {
    abcpwn::core::Context ctx;
    ctx.format = abcpwn::core::OutputFormat::Json;
    ctx.color = abcpwn::core::ColorMode::Always;
    std::ostringstream oss;
    REQUIRE_FALSE(abcpwn::output::PrettyPrinter::should_color(ctx, oss));
}
