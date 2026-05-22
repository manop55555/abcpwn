// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/b64.hpp"
#include "abcpwn/commands/constgrep.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/commands/errno_cmd.hpp"
#include "abcpwn/commands/hex.hpp"
#include "abcpwn/commands/pack.hpp"
#include "abcpwn/commands/xor_cmd.hpp"
#include "abcpwn/core/context.hpp"

using namespace abcpwn::commands;
using namespace abcpwn::commands::encoding;

namespace {
std::vector<std::uint8_t> as_bytes(std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()),
            reinterpret_cast<const std::uint8_t*>(s.data()) + s.size()};
}
} // namespace

TEST_CASE("pack writes little-endian by default", "[encoding][pack]") {
    auto r = pack(0x4142, 2, Endian::Little);
    REQUIRE(r);
    REQUIRE(r->size() == 2);
    REQUIRE((*r)[0] == 0x42);
    REQUIRE((*r)[1] == 0x41);
}

TEST_CASE("pack big-endian roundtrip", "[encoding][pack]") {
    auto r = pack(0xdeadbeef, 4, Endian::Big);
    REQUIRE(r);
    REQUIRE(hex_encode(*r) == "deadbeef");

    auto v = unpack(*r, Endian::Big);
    REQUIRE(v);
    REQUIRE(*v == 0xdeadbeef);
}

TEST_CASE("pack rejects unsupported width", "[encoding][pack]") {
    REQUIRE_FALSE(pack(0, 3, Endian::Little));
    REQUIRE_FALSE(pack(0, 16, Endian::Little));
}

TEST_CASE("hex roundtrip", "[encoding][hex]") {
    const auto bytes = as_bytes("Hello");
    REQUIRE(hex_encode(bytes) == "48656c6c6f");
    auto back = hex_decode("48656c6c6f");
    REQUIRE(back);
    REQUIRE(std::string(reinterpret_cast<const char*>(back->data()), back->size()) == "Hello");
}

TEST_CASE("hex tolerates separators and whitespace", "[encoding][hex]") {
    auto r = hex_decode("48 65:6c-6c,6f");
    REQUIRE(r);
    REQUIRE(r->size() == 5);
    REQUIRE((*r)[0] == 'H');
}

TEST_CASE("hex rejects odd digits and bad chars", "[encoding][hex]") {
    REQUIRE_FALSE(hex_decode("abc"));
    REQUIRE_FALSE(hex_decode("zz"));
}

TEST_CASE("base64 known vectors", "[encoding][base64]") {
    REQUIRE(base64_encode(as_bytes("f")) == "Zg==");
    REQUIRE(base64_encode(as_bytes("fo")) == "Zm8=");
    REQUIRE(base64_encode(as_bytes("foo")) == "Zm9v");
    REQUIRE(base64_encode(as_bytes("foob")) == "Zm9vYg==");
    REQUIRE(base64_encode(as_bytes("fooba")) == "Zm9vYmE=");
    REQUIRE(base64_encode(as_bytes("foobar")) == "Zm9vYmFy");
}

TEST_CASE("base64 roundtrip", "[encoding][base64]") {
    const auto bytes = as_bytes("any carnal pleasure.");
    const auto enc = base64_encode(bytes);
    auto dec = base64_decode(enc);
    REQUIRE(dec);
    REQUIRE(std::vector<std::uint8_t>(*dec) == bytes);
}

TEST_CASE("base64 rejects malformed input", "[encoding][base64]") {
    REQUIRE_FALSE(base64_decode("Zm9=v")); // data after pad
    REQUIRE_FALSE(base64_decode("***"));
}

TEST_CASE("xor repeats key", "[encoding][xor]") {
    const std::vector<std::uint8_t> data{0x41, 0x42, 0x43, 0x44};
    const std::vector<std::uint8_t> key{0x01, 0x02};
    auto out = xor_with_key(data, key);
    REQUIRE(out == std::vector<std::uint8_t>{0x40, 0x40, 0x42, 0x46});
}

TEST_CASE("errno lookup by name and number", "[encoding][errno]") {
    REQUIRE(errno_by_name("ENOENT")->number == 2);
    REQUIRE(errno_by_number(13)->name == "EACCES");
    REQUIRE(errno_by_number(99999) == nullptr);
}

TEST_CASE("constgrep finds signals", "[encoding][constgrep]") {
    auto hits = constgrep_search("SIGINT");
    REQUIRE_FALSE(hits.empty());
    REQUIRE(hits[0].value == 2);

    auto cat = constgrep_search("KILL", "signal");
    REQUIRE_FALSE(cat.empty());
    REQUIRE(cat[0].value == 9);
}

TEST_CASE("PackCommand runs end-to-end", "[encoding][command]") {
    abcpwn::core::Context ctx;
    PackCommand p;
    p.value = 0x4142;
    p.width = 2;
    p.big_endian = false;
    auto r = p.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0] == "4241");
}

TEST_CASE("HexCommand runs end-to-end", "[encoding][command]") {
    abcpwn::core::Context ctx;
    HexCommand h;
    h.input = "ABC";
    auto r = h.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0] == "414243");
}

TEST_CASE("ErrnoCommand by name", "[encoding][command]") {
    abcpwn::core::Context ctx;
    ErrnoCommand e;
    e.query = "EACCES";
    auto r = e.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    REQUIRE(r->sections[0].findings.size() == 1);
    REQUIRE(r->sections[0].findings[0].title == "EACCES");
}

TEST_CASE("ConstgrepCommand finds entries", "[encoding][command]") {
    abcpwn::core::Context ctx;
    ConstgrepCommand c;
    c.query = "PROT_EXEC";
    auto r = c.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    REQUIRE(r->sections[0].findings.size() == 1);
}
