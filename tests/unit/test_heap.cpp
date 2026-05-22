// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/heap.hpp"
#include "abcpwn/commands/safe_link.hpp"
#include "abcpwn/core/context.hpp"

#include <catch2/catch_test_macros.hpp>

#include <charconv>
#include <cstdint>
#include <set>
#include <string>
#include <system_error>
#include <utility>

using namespace abcpwn::commands;

// --- heap compatibility matrix -----------------------------------------------

TEST_CASE("technique_from_string covers every v0.1 technique", "[heap]") {
    REQUIRE(*heap::technique_from_string("tcache-poison")   == heap::Technique::TcachePoison);
    REQUIRE(*heap::technique_from_string("fastbin")         == heap::Technique::Fastbin);
    REQUIRE(*heap::technique_from_string("house-of-force")  == heap::Technique::HouseOfForce);
    REQUIRE(*heap::technique_from_string("house-of-orange") == heap::Technique::HouseOfOrange);
    REQUIRE(*heap::technique_from_string("house-of-apple")  == heap::Technique::HouseOfApple);
    REQUIRE(*heap::technique_from_string("unsorted-bin")    == heap::Technique::UnsortedBin);
    REQUIRE_FALSE(heap::technique_from_string("does-not-exist").has_value());
}

TEST_CASE("libc_era_from_string accepts the four spec values plus 2.23", "[heap]") {
    REQUIRE(*heap::libc_era_from_string("2.23") == heap::LibcEra::V2_23);
    REQUIRE(*heap::libc_era_from_string("2.27") == heap::LibcEra::V2_27);
    REQUIRE(*heap::libc_era_from_string("2.31") == heap::LibcEra::V2_31);
    REQUIRE(*heap::libc_era_from_string("2.34") == heap::LibcEra::V2_34);
    REQUIRE(*heap::libc_era_from_string("2.39") == heap::LibcEra::V2_39);
    REQUIRE_FALSE(heap::libc_era_from_string("2.40").has_value());
}

TEST_CASE("compatibility matrix is exhaustive across techniques x eras", "[heap]") {
    // 6 techniques x 5 eras = 30 entries
    REQUIRE(heap::compatibility_matrix().size() == 30);
    std::set<std::pair<int, int>> seen;
    for (const auto& row : heap::compatibility_matrix()) {
        auto key = std::make_pair(
            static_cast<int>(row.technique), static_cast<int>(row.libc));
        REQUIRE(seen.insert(key).second);  // no duplicates
    }
    REQUIRE(seen.size() == 30);
}

TEST_CASE("known per-technique status: House of Force dies in 2.31+", "[heap]") {
    // The technique was killed in 2.29 by the top-chunk size sanity
    // check. Anything 2.31+ must be marked Broken in the matrix.
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfForce, heap::LibcEra::V2_27).status
        == heap::Status::Works);
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfForce, heap::LibcEra::V2_31).status
        == heap::Status::Broken);
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfForce, heap::LibcEra::V2_34).status
        == heap::Status::Broken);
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfForce, heap::LibcEra::V2_39).status
        == heap::Status::Broken);
}

TEST_CASE("known per-technique status: tcache poison broken before 2.27", "[heap]") {
    REQUIRE(heap::lookup_compat(heap::Technique::TcachePoison, heap::LibcEra::V2_23).status
        == heap::Status::Broken);
    REQUIRE(heap::lookup_compat(heap::Technique::TcachePoison, heap::LibcEra::V2_27).status
        == heap::Status::Works);
}

TEST_CASE("known per-technique status: House of Apple post-2.30 only", "[heap]") {
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfApple, heap::LibcEra::V2_23).status
        == heap::Status::Broken);
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfApple, heap::LibcEra::V2_27).status
        == heap::Status::Broken);
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfApple, heap::LibcEra::V2_31).status
        == heap::Status::Works);
    REQUIRE(heap::lookup_compat(heap::Technique::HouseOfApple, heap::LibcEra::V2_34).status
        == heap::Status::Works);
}

TEST_CASE("HeapCommand single-era output names status + rationale", "[heap][command]") {
    abcpwn::core::Context ctx;
    heap::HeapCommand cmd;
    cmd.technique_str    = "tcache-poison";
    cmd.libc_version_str = "2.39";
    cmd.target_address   = 0x404040;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool saw_status = false;
    bool saw_target = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "status" && f.detail == "MITIGATED") saw_status = true;
            if (f.title == "target" && f.detail.find("0x404040") != std::string::npos)
                saw_target = true;
        }
    }
    REQUIRE(saw_status);
    REQUIRE(saw_target);
}

TEST_CASE("HeapCommand --all-libcs lists every era for the technique", "[heap][command]") {
    abcpwn::core::Context ctx;
    heap::HeapCommand cmd;
    cmd.technique_str = "house-of-force";
    cmd.all_libcs     = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    // 5 findings for the 5 libc eras
    REQUIRE(r->sections[0].findings.size() == 5);
}

TEST_CASE("HeapCommand unknown technique is a usage error", "[heap][command]") {
    abcpwn::core::Context ctx;
    heap::HeapCommand cmd;
    cmd.technique_str = "house-of-nope";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

TEST_CASE("HeapCommand unknown libc version is a usage error", "[heap][command]") {
    abcpwn::core::Context ctx;
    heap::HeapCommand cmd;
    cmd.technique_str    = "fastbin";
    cmd.libc_version_str = "2.99";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

// --- safe-link ---------------------------------------------------------------

TEST_CASE("safe_link encode then decode round-trips", "[safe-link]") {
    constexpr std::uint64_t ptr = 0x55aabbccdd001000ULL;
    constexpr std::uint64_t pos = 0x55aabbccdd002400ULL;
    const auto enc = safe_link::safe_link_encode(ptr, pos);
    REQUIRE(enc != ptr);
    REQUIRE(safe_link::safe_link_decode(enc, pos) == ptr);
}

TEST_CASE("safe_link is identity when pos < 0x1000", "[safe-link]") {
    constexpr std::uint64_t ptr = 0xdeadbeef;
    REQUIRE(safe_link::safe_link_encode(ptr, 0xfff) == ptr);
    REQUIRE(safe_link::safe_link_encode(ptr, 0)     == ptr);
}

TEST_CASE("SafeLinkCommand --encode emits hex result", "[safe-link][command]") {
    abcpwn::core::Context ctx;
    safe_link::SafeLinkCommand cmd;
    cmd.ptr_or_encoded = 0x55aabbccdd000000ULL;
    cmd.pos            = 0x55aabbccdd003000ULL;
    cmd.encode         = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    REQUIRE(r->raw_lines[0].starts_with("0x"));
}

TEST_CASE("SafeLinkCommand rejects pos=0", "[safe-link][command]") {
    abcpwn::core::Context ctx;
    safe_link::SafeLinkCommand cmd;
    cmd.ptr_or_encoded = 0x1234;
    cmd.pos            = 0;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::InvalidInput);
}

TEST_CASE("SafeLinkCommand encode + decode round-trips through the command", "[safe-link][command]") {
    abcpwn::core::Context ctx;
    constexpr std::uint64_t ptr = 0x7fff12345678ULL;
    constexpr std::uint64_t pos = 0x7fff12349000ULL;

    safe_link::SafeLinkCommand enc;
    enc.ptr_or_encoded = ptr;
    enc.pos            = pos;
    enc.encode         = true;
    auto enc_r = enc.run(ctx);
    REQUIRE(enc_r);
    const std::string enc_hex = enc_r->raw_lines[0];

    // Parse back the encoded hex
    std::uint64_t encoded = 0;
    REQUIRE(enc_hex.starts_with("0x"));
    const auto* begin = enc_hex.data() + 2;
    const auto* end   = enc_hex.data() + enc_hex.size();
    auto fc = std::from_chars(begin, end, encoded, 16);
    REQUIRE(fc.ec == std::errc{});

    safe_link::SafeLinkCommand dec;
    dec.ptr_or_encoded = encoded;
    dec.pos            = pos;
    dec.encode         = false;
    auto dec_r = dec.run(ctx);
    REQUIRE(dec_r);
    REQUIRE(dec_r->raw_lines[0] == "0x7fff12345678");
}
