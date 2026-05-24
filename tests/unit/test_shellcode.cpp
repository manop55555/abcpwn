// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/commands/shellcode.hpp"
#include "abcpwn/core/context.hpp"

using namespace abcpwn::commands::shellcode;

TEST_CASE("preset_from_string accepts only DB-backed names", "[shellcode]") {
    REQUIRE(*preset_from_string("sh") == Preset::Sh);
    // Names enumerated in the Preset enum but absent from the v0.1
    // database (read-flag, cat-flag, bind, reverse) must NOT parse;
    // accepting them at parse time and failing later in lookup()
    // produced confusing error messages and inconsistent --help /
    // --list output.
    REQUIRE_FALSE(preset_from_string("read-flag").has_value());
    REQUIRE_FALSE(preset_from_string("cat-flag").has_value());
    REQUIRE_FALSE(preset_from_string("bind").has_value());
    REQUIRE_FALSE(preset_from_string("reverse").has_value());
    REQUIRE_FALSE(preset_from_string("nope").has_value());
}

TEST_CASE("database has the curated x86_64 / x86 / aarch64 sh entries", "[shellcode][db]") {
    const auto db = database();
    REQUIRE(db.size() == 3);
    bool has_x64_sh = false;
    bool has_x86_sh = false;
    bool has_a64_sh = false;
    for (const auto& e : db) {
        if (e.arch == abcpwn::arch::Arch::X86_64 && e.preset == Preset::Sh)
            has_x64_sh = true;
        if (e.arch == abcpwn::arch::Arch::X86 && e.preset == Preset::Sh)
            has_x86_sh = true;
        if (e.arch == abcpwn::arch::Arch::Aarch64 && e.preset == Preset::Sh)
            has_a64_sh = true;
        REQUIRE_FALSE(e.bytes.empty());
        REQUIRE(e.bytes.size() < 256); // sanity
    }
    REQUIRE(has_x64_sh);
    REQUIRE(has_x86_sh);
    REQUIRE(has_a64_sh);
}

TEST_CASE("x86_64 sh payload has expected syscall trailer", "[shellcode]") {
    PayloadSpec spec;
    spec.arch = abcpwn::arch::Arch::X86_64;
    spec.preset = Preset::Sh;
    auto p = lookup(spec);
    REQUIRE(p);
    // 24 bytes after the QA round-2 NUL-terminator fix (was 23
    // pre-fix; an extra `push rdx` was inserted to guarantee
    // [rdi+8] == 0 on the stack).
    REQUIRE(p->bytes.size() == 24);
    // last two bytes must be 0x0f 0x05 (syscall)
    REQUIRE(p->bytes[p->bytes.size() - 2] == 0x0f);
    REQUIRE(p->bytes[p->bytes.size() - 1] == 0x05);
    // and 0x3b (execve) must appear early (the "push 0x3b" pattern)
    REQUIRE(p->bytes[0] == 0x6a);
    REQUIRE(p->bytes[1] == 0x3b);
    // The NUL-terminator fix is structurally identified by a
    // `push rdx` (0x52) appearing BEFORE the movabs rbx
    // (0x48 0xbb) - that pushed zero is what lands at [rdi+8]
    // and terminates the pathname.
    REQUIRE(p->bytes[4] == 0x52);
    REQUIRE(p->bytes[5] == 0x48);
    REQUIRE(p->bytes[6] == 0xbb);
}

TEST_CASE("x86 sh payload uses int 0x80", "[shellcode]") {
    PayloadSpec spec;
    spec.arch = abcpwn::arch::Arch::X86;
    spec.preset = Preset::Sh;
    auto p = lookup(spec);
    REQUIRE(p);
    REQUIRE(p->bytes.size() == 25);
    REQUIRE(p->bytes[p->bytes.size() - 2] == 0xcd);
    REQUIRE(p->bytes[p->bytes.size() - 1] == 0x80);
}

TEST_CASE("aarch64 sh payload ends with svc #0", "[shellcode]") {
    PayloadSpec spec;
    spec.arch = abcpwn::arch::Arch::Aarch64;
    spec.preset = Preset::Sh;
    auto p = lookup(spec);
    REQUIRE(p);
    REQUIRE(p->bytes.size() == 40);
    // svc #0 is 0x01 0x00 0x00 0xd4 (little-endian instruction word)
    REQUIRE(p->bytes[36] == 0x01);
    REQUIRE(p->bytes[37] == 0x00);
    REQUIRE(p->bytes[38] == 0x00);
    REQUIRE(p->bytes[39] == 0xd4);
}

TEST_CASE("lookup returns Unsupported for unknown combinations", "[shellcode]") {
    PayloadSpec spec;
    spec.arch = abcpwn::arch::Arch::Aarch64;
    spec.preset = Preset::Bind;
    auto p = lookup(spec);
    REQUIRE_FALSE(p);
    REQUIRE(p.error().code == abcpwn::core::ErrorCode::Unsupported);
    REQUIRE(p.error().message.find("subsequent releases") != std::string::npos);
}

TEST_CASE("payloads marked null_free actually have no 0x00 bytes", "[shellcode][db]") {
    for (const auto& e : database()) {
        if (!e.null_free)
            continue;
        for (auto b : e.bytes) {
            REQUIRE(b != 0x00);
        }
    }
}

TEST_CASE("xor encoder roundtrips", "[shellcode][encoder]") {
    const std::vector<std::uint8_t> input{0x90, 0x90, 0x6a, 0x3b, 0x58, 0x0f, 0x05};
    Encoder enc;
    enc.kind = Encoder::Kind::Xor;
    enc.key = {0xa5};

    auto encoded = apply_encoder(input, enc);
    REQUIRE(encoded);
    REQUIRE(encoded->bytes.size() == input.size());
    REQUIRE(encoded->bytes != input);

    // XOR the encoded bytes with the same key -> original
    auto round = abcpwn::commands::encoding::xor_with_key(encoded->bytes, enc.key);
    REQUIRE(round == input);
}

TEST_CASE("xor encoder rejects empty key", "[shellcode][encoder]") {
    Encoder enc;
    enc.kind = Encoder::Kind::Xor;
    auto r = apply_encoder(std::span<const std::uint8_t>{}, enc);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::InvalidInput);
}

TEST_CASE("null-free encoder verifies absence of 0x00", "[shellcode][encoder]") {
    Encoder enc;
    enc.kind = Encoder::Kind::NullFree;
    std::vector<std::uint8_t> good{0x6a, 0x3b};
    std::vector<std::uint8_t> bad{0x6a, 0x00, 0x3b};

    REQUIRE(apply_encoder(good, enc));
    auto bad_r = apply_encoder(bad, enc);
    REQUIRE_FALSE(bad_r);
    REQUIRE(bad_r.error().code == abcpwn::core::ErrorCode::InvalidInput);
}

TEST_CASE("printable / alpha encoders surface Unsupported", "[shellcode][encoder]") {
    Encoder enc;
    enc.kind = Encoder::Kind::Printable;
    REQUIRE_FALSE(apply_encoder(std::span<const std::uint8_t>{}, enc));
    enc.kind = Encoder::Kind::Alpha;
    REQUIRE_FALSE(apply_encoder(std::span<const std::uint8_t>{}, enc));
}

TEST_CASE("ShellcodeCommand --list enumerates the database", "[shellcode][command]") {
    abcpwn::core::Context ctx;
    ShellcodeCommand cmd;
    cmd.list = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    REQUIRE(r->sections[0].findings.size() == database().size());
}

TEST_CASE("ShellcodeCommand default x86_64 sh in hex format", "[shellcode][command]") {
    abcpwn::core::Context ctx;
    ShellcodeCommand cmd;
    cmd.preset_str = "sh";
    cmd.arch_str = "x86_64";
    cmd.format = "hex";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    // 24 bytes (after the round-2 NUL-terminator fix) * 2 hex chars
    REQUIRE(r->raw_lines[0].size() == 48);
    REQUIRE(r->raw_lines[0].starts_with("6a3b58"));
}

TEST_CASE("ShellcodeCommand bad-chars filter rejects matching payload", "[shellcode][command]") {
    abcpwn::core::Context ctx;
    ShellcodeCommand cmd;
    cmd.preset_str = "sh";
    cmd.arch_str = "x86_64";
    cmd.bad_chars_hex = "0f"; // x86_64 sh contains 0x0f (syscall opcode)
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::InvalidInput);
    REQUIRE(r.error().message.find("0x0f") != std::string::npos);
}

TEST_CASE("ShellcodeCommand format=c emits a C array literal", "[shellcode][command]") {
    abcpwn::core::Context ctx;
    ShellcodeCommand cmd;
    cmd.preset_str = "sh";
    cmd.arch_str = "x86";
    cmd.format = "c";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 1);
    const auto& s = r->raw_lines[0];
    REQUIRE(s.find("unsigned char shellcode[25]") == 0);
    REQUIRE(s.find("0x31, 0xc0") != std::string::npos);
}
