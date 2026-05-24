// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <chrono>
#include <sstream>

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"
#include "abcpwn/core/version.hpp"
#include "abcpwn/output/json_writer.hpp"

using nlohmann::json;

namespace {

abcpwn::core::CommandResult sample_result() {
    abcpwn::core::CommandResult res;
    res.duration = std::chrono::milliseconds{12};
    auto& s = res.sections.emplace_back();
    s.title = "Mitigations";
    s.findings.emplace_back(abcpwn::core::Severity::Info, "NX", "yes");
    s.findings.emplace_back(abcpwn::core::Severity::High, "Fortify", "no");
    s.findings.emplace_back(abcpwn::core::Severity::Low, "Stripped", "no");
    return res;
}

} // namespace

TEST_CASE("json envelope carries required envelope fields", "[json]") {
    abcpwn::core::Context ctx;
    ctx.format = abcpwn::core::OutputFormat::Json;
    abcpwn::output::JsonWriter w(ctx);
    std::ostringstream oss;
    w.write(oss, "info", sample_result(), {{"binary", std::string("/bin/ls")}});

    const auto j = json::parse(oss.str());
    // N3: the JSON envelope reports the build-time SemVer (the single
    // source shared with the banner and --version), not a hardcoded
    // MAJOR.MINOR.PATCH.
    REQUIRE(j["abcpwn_version"].get<std::string>() == std::string(abcpwn::core::semver_string));
    REQUIRE(j["schema_version"].get<int>() == 1);
    REQUIRE(j["command"].get<std::string>() == "info");
    REQUIRE(j["args"]["binary"].get<std::string>() == "/bin/ls");
    REQUIRE(j["duration_ms"].get<int>() == 12);
    REQUIRE(j.contains("result"));
    REQUIRE(j.contains("findings"));
    REQUIRE(j.contains("summary"));
}

TEST_CASE("json summary counts findings by severity", "[json]") {
    abcpwn::core::Context ctx;
    abcpwn::output::JsonWriter w(ctx);
    std::ostringstream oss;
    w.write(oss, "info", sample_result());
    const auto j = json::parse(oss.str());

    REQUIRE(j["summary"]["info"].get<int>() == 1);
    REQUIRE(j["summary"]["low"].get<int>() == 1);
    REQUIRE(j["summary"]["high"].get<int>() == 1);
    REQUIRE(j["summary"]["medium"].get<int>() == 0);
    REQUIRE(j["summary"]["critical"].get<int>() == 0);
}

TEST_CASE("json findings array preserves order and severity strings", "[json]") {
    abcpwn::core::Context ctx;
    abcpwn::output::JsonWriter w(ctx);
    std::ostringstream oss;
    w.write(oss, "info", sample_result());
    const auto j = json::parse(oss.str());

    const auto& f = j["findings"];
    REQUIRE(f.size() == 3);
    REQUIRE(f[0]["severity"].get<std::string>() == "info");
    REQUIRE(f[1]["severity"].get<std::string>() == "high");
    REQUIRE(f[2]["severity"].get<std::string>() == "low");
    REQUIRE(f[0]["title"].get<std::string>() == "NX");
}

TEST_CASE("json result.exit_code defaults to zero", "[json]") {
    abcpwn::core::Context ctx;
    abcpwn::output::JsonWriter w(ctx);
    std::ostringstream oss;
    abcpwn::core::CommandResult res;
    w.write(oss, "noop", res);
    const auto j = json::parse(oss.str());
    REQUIRE(j["result"]["exit_code"].get<int>() == 0);
}

TEST_CASE("json raw_payload encodes binary bytes as base64 + hex", "[json][raw-bytes]") {
    abcpwn::core::Context ctx;
    ctx.format = abcpwn::core::OutputFormat::Json;
    abcpwn::output::JsonWriter w(ctx);
    std::ostringstream oss;
    abcpwn::core::CommandResult res;
    res.raw_payload = true;
    // Non-UTF-8 bytes that previously aborted nlohmann::dump.
    res.raw_lines.emplace_back(std::string{"\xde\xad\xbe\xef", 4});

    // Must not throw / abort.
    REQUIRE_NOTHROW(w.write(oss, "unhex", res));

    const auto j = json::parse(oss.str());
    REQUIRE(j["result"]["bytes_b64"].get<std::string>() == "3q2+7w==");
    REQUIRE(j["result"]["bytes_hex"].get<std::string>() == "deadbeef");
    REQUIRE(j["result"]["bytes_len"].get<int>() == 4);
    // The legacy "lines" field is not present for raw_payload so
    // downstream tools never see a string holding raw bytes.
    REQUIRE_FALSE(j["result"].contains("lines"));
}

TEST_CASE("json raw_payload handles all 256 byte values", "[json][raw-bytes]") {
    abcpwn::core::Context ctx;
    ctx.format = abcpwn::core::OutputFormat::Json;
    abcpwn::output::JsonWriter w(ctx);
    std::ostringstream oss;
    abcpwn::core::CommandResult res;
    res.raw_payload = true;
    std::string all;
    all.reserve(256);
    for (int i = 0; i < 256; ++i) {
        all.push_back(static_cast<char>(i));
    }
    res.raw_lines.push_back(all);

    REQUIRE_NOTHROW(w.write(oss, "noop", res));
    const auto j = json::parse(oss.str());
    REQUIRE(j["result"]["bytes_len"].get<int>() == 256);
    // Spot-check a couple bytes via the hex representation.
    const auto hex = j["result"]["bytes_hex"].get<std::string>();
    REQUIRE(hex.substr(0, 4) == "0001");
    REQUIRE(hex.substr(508, 4) == "feff");
}
