// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/libc.hpp"
#include "abcpwn/commands/seccomp.hpp"
#include "abcpwn/core/context.hpp"

// --- seccomp -----------------------------------------------------------------

TEST_CASE("decode_bpf splits an 8-byte sequence into one instruction", "[seccomp]") {
    // BPF_LD | BPF_W | BPF_ABS, k=0  -> "A = sys_number"
    // code = 0x20 (BPF_ABS | BPF_W=0 | BPF_LD=0)
    const std::vector<std::uint8_t> bytes{0x20, 0x00, 0, 0, 0, 0, 0, 0};
    auto r = abcpwn::commands::seccomp::decode_bpf(bytes);
    REQUIRE(r);
    REQUIRE(r->size() == 1);
    REQUIRE((*r)[0].code == 0x20);
    REQUIRE((*r)[0].k == 0);
}

TEST_CASE("decode_bpf refuses an unaligned buffer", "[seccomp]") {
    auto r =
        abcpwn::commands::seccomp::decode_bpf({reinterpret_cast<const std::uint8_t*>("abc"), 3});
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::InvalidInput);
}

TEST_CASE("disassemble_bpf renders the canonical seccomp prelude", "[seccomp]") {
    using namespace abcpwn::commands::seccomp;
    std::vector<BpfInsn> prog;
    // 0: A = sys_number    (BPF_LD | BPF_W | BPF_ABS, k=0)
    prog.push_back({0x20, 0, 0, 0});
    // 1: if (A == 59) goto +1 else +0   ; SYS_execve on x86_64
    prog.push_back({0x15, 1, 0, 59});
    // 2: return ALLOW
    prog.push_back({0x06, 0, 0, 0x7fff0000U});
    // 3: return KILL
    prog.push_back({0x06, 0, 0, 0});

    const auto lines = disassemble_bpf(prog, abcpwn::arch::Arch::X86_64);
    REQUIRE(lines.size() == 4);
    REQUIRE(lines[0].find("A = sys_number") != std::string::npos);
    REQUIRE(lines[1].find("if (A == 0x3b)") != std::string::npos);
    REQUIRE(lines[1].find("SYS_execve") != std::string::npos);
    REQUIRE(lines[2].find("return ALLOW") != std::string::npos);
    REQUIRE(lines[3].find("return KILL") != std::string::npos);
}

TEST_CASE("SeccompCommand disasm action runs end-to-end", "[seccomp][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::seccomp::SeccompCommand cmd;
    cmd.action = "disasm";
    // Hex-encode the same 4-instruction program as above.
    cmd.input = "20000000"
                "00000000" // A = sys_number
                "15000100"
                "3b000000" // if (A == 0x3b) ALLOW
                "06000000"
                "0000ff7f" // return ALLOW
                "06000000"
                "00000000"; // return KILL
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->raw_lines.size() == 4);
    REQUIRE(r->summary.has_value());
    REQUIRE(r->summary->find("4 BPF") != std::string::npos);
}

TEST_CASE("SeccompCommand surfaces Unsupported for dump / asm / emu", "[seccomp][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::seccomp::SeccompCommand cmd;
    for (const auto& a : {std::string("dump"), std::string("asm"), std::string("emu")}) {
        cmd.action = a;
        cmd.input = "x";
        auto r = cmd.run(ctx);
        REQUIRE_FALSE(r);
        REQUIRE(r.error().code == abcpwn::core::ErrorCode::Unsupported);
    }
}

// --- libc -------------------------------------------------------------------

TEST_CASE("libc id round-trips a known glibc 2.34 fingerprint", "[libc][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action = "id";
    // glibc 2.34 puts low12=0x550 (system), 0xd30 (execve)
    cmd.offset_pairs = {"system:0x550", "execve:0xd30"};
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool found = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.detail.find("libc6_2.34") != std::string::npos)
                found = true;
        }
    }
    REQUIRE(found);
}

TEST_CASE("libc offsets surfaces every symbol for a known id", "[libc][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action = "offsets";
    cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    REQUIRE(r->sections[0].findings.size() >= 4);
}

TEST_CASE("libc offsets --symbol filters", "[libc][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action = "offsets";
    cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
    cmd.symbol = "system";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->sections[0].findings.size() == 1);
    REQUIRE(r->sections[0].findings[0].title == "system");
}

TEST_CASE("libc download requires --allow-network in Context", "[libc][command]") {
    abcpwn::core::Context ctx;
    ctx.allow_network = false;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action = "download";
    cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::NetworkDisabled);
}

TEST_CASE("libc download surfaces FeatureDisabled when build lacks network", "[libc][command]") {
    if (abcpwn::commands::libc::network_compiled_in()) {
        SKIP("network was compiled in; the FeatureDisabled path is not active");
    }
    abcpwn::core::Context ctx;
    ctx.allow_network = true; // pass the runtime gate so we hit the compile-time gate
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action = "download";
    cmd.identifier = "libc6_2.34-0ubuntu3_amd64";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::FeatureDisabled);
}

TEST_CASE("libc search filters in-binary table by substring", "[libc][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::libc::LibcCommand cmd;
    cmd.action = "search";
    cmd.identifier = "2.39";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool any_2_39 = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title.find("2.39") != std::string::npos)
                any_2_39 = true;
        }
    }
    REQUIRE(any_2_39);
}
