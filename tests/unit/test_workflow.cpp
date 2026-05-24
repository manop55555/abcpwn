// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/commands/diff.hpp"
#include "abcpwn/commands/patch.hpp"
#include "abcpwn/commands/pwn.hpp"
#include "abcpwn/commands/pwninit.hpp"
#include "abcpwn/commands/template_cmd.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

namespace {

std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}

std::filesystem::path tmp_dir() {
    auto base = std::filesystem::temp_directory_path() / "abcpwn-test";
    std::filesystem::create_directories(base);
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    auto d = base / ("workflow-" + std::to_string(rng()));
    std::filesystem::create_directories(d);
    return d;
}

} // namespace

// --- pwn target parser + DSL -------------------------------------------------

TEST_CASE("pwn parse_target accepts host:port, unix:, and ./local", "[pwn]") {
    using namespace abcpwn::commands::pwn;
    auto tcp = parse_target("1.2.3.4:1337");
    REQUIRE(tcp);
    REQUIRE(tcp->kind == TubeKind::Tcp);
    REQUIRE(tcp->host_or_path == "1.2.3.4");
    REQUIRE(tcp->port == 1337);

    auto un = parse_target("unix:/tmp/sock");
    REQUIRE(un);
    REQUIRE(un->kind == TubeKind::UnixSocket);
    REQUIRE(un->host_or_path == "/tmp/sock");

    auto proc = parse_target("./bin");
    REQUIRE(proc);
    REQUIRE(proc->kind == TubeKind::Process);
}

TEST_CASE("pwn DSL parses every supported op", "[pwn]") {
    using namespace abcpwn::commands::pwn;
    const std::string src = "# comment line\n"
                            "recvuntil >>>\n"
                            "send AAAA\n"
                            "sendline payload\n"
                            "recvline\n"
                            "recvn 16\n"
                            "sleep 100\n"
                            "expect ^prompt$\n"
                            "set var some-value\n";
    auto r = parse_dsl(src);
    REQUIRE(r);
    REQUIRE(r->size() == 8);
    REQUIRE((*r)[0].op == DslOp::RecvUntil);
    REQUIRE((*r)[4].numeric == 16);
    REQUIRE((*r)[5].numeric == 100);
    REQUIRE((*r)[7].arg1 == "var");
    REQUIRE((*r)[7].arg2 == "some-value");
}

TEST_CASE("pwn DSL rejects unknown ops and missing args", "[pwn]") {
    using namespace abcpwn::commands::pwn;
    REQUIRE_FALSE(parse_dsl("madeup foo\n"));
    REQUIRE_FALSE(parse_dsl("send\n"));      // missing arg
    REQUIRE_FALSE(parse_dsl("recvn abc\n")); // non-numeric
}

TEST_CASE("PwnCommand reports NotImplemented for every mode (DEF-9)", "[pwn][command]") {
    abcpwn::core::Context ctx;
    // DEF-9: until the live tube driver lands (Tier F), every mode returns
    // NotImplemented -- not a false-success "plan" at rc=0 (tcp/unix) and
    // not an Unsupported error that leaks internal source-policy text
    // (local). The target is still validated, so a malformed one errors.
    for (const char* target : {"./somebin", "127.0.0.1:31337", "unix:/tmp/sock"}) {
        abcpwn::commands::pwn::PwnCommand cmd;
        cmd.target = target;
        auto r = cmd.run(ctx);
        REQUIRE_FALSE(r);
        REQUIRE(r.error().code == abcpwn::core::ErrorCode::NotImplemented);
        REQUIRE(r.error().message.find("src/") == std::string::npos);
        REQUIRE(r.error().message.find("posix_spawn") == std::string::npos);
    }
}

// --- pwninit -----------------------------------------------------------------

TEST_CASE("PwninitCommand reports steps without doing network", "[pwninit][command]") {
    abcpwn::core::Context ctx;
    ctx.allow_network = false;
    abcpwn::commands::pwninit::PwninitCommand cmd;
    cmd.directory = "/nonexistent-dir-that-should-not-trigger";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    // expects two sections: pwninit plan + steps that would execute
    REQUIRE(r->sections.size() == 2);
    REQUIRE_FALSE(r->sections[0].findings.empty());
    REQUIRE_FALSE(r->sections[1].findings.empty());
}

// --- template ----------------------------------------------------------------

TEST_CASE("render_template ret2libc produces a pwntools-shaped script", "[template]") {
    using abcpwn::commands::tmpl::render_template;
    const auto s = render_template("ret2libc", "/bin/ls");
    REQUIRE(s.find("from pwn import *") != std::string::npos);
    REQUIRE(s.find("elf = ELF(\"/bin/ls\")") != std::string::npos);
    REQUIRE(s.find("libc.symbols['puts']") != std::string::npos);
    REQUIRE(s.find("libc.symbols['system']") != std::string::npos);
}

TEST_CASE("TemplateCommand writes solve.py when -o is given", "[template][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::tmpl::TemplateCommand cmd;
    cmd.strategy = "ret2win";
    cmd.binary_path = "./chal";
    const auto d = tmp_dir();
    cmd.output_path = (d / "solve.py").string();
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(std::filesystem::exists(cmd.output_path));
    std::ifstream in(cmd.output_path);
    std::string content((std::istreambuf_iterator<char>(in)), {});
    REQUIRE(content.find("ret2win") != std::string::npos);
    std::filesystem::remove_all(d);
}

// --- diff / patch ------------------------------------------------------------

TEST_CASE("byte_diff finds the exact bytes that differ", "[diff]") {
    using abcpwn::commands::diffpatch::byte_diff;
    const std::vector<std::uint8_t> a{0x00, 0xaa, 0xbb, 0xcc};
    const std::vector<std::uint8_t> b{0x00, 0xaa, 0x42, 0xcc, 0x77};
    auto deltas = byte_diff(a, b);
    REQUIRE(deltas.size() == 2);
    REQUIRE(deltas[0].offset == 2);
    REQUIRE(deltas[0].a == 0xbb);
    REQUIRE(deltas[0].b == 0x42);
    REQUIRE(deltas[1].offset == 4);
}

TEST_CASE("DiffCommand on identical files reports (identical)", "[diff][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::diffpatch::DiffCommand cmd;
    cmd.file_a = fixture("hello-hardened").string();
    cmd.file_b = fixture("hello-hardened").string();
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool saw_identical = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "(identical)")
                saw_identical = true;
        }
    }
    REQUIRE(saw_identical);
}

TEST_CASE("PatchCommand writes .patched with byte patch applied", "[patch][command]") {
    abcpwn::core::Context ctx;
    const auto d = tmp_dir();
    const auto src = d / "target.bin";
    {
        std::ofstream out(src, std::ios::binary);
        const std::string content(16, 'A');
        out.write(content.data(), content.size());
    }
    abcpwn::commands::diffpatch::PatchCommand cmd;
    cmd.target = src.string();
    cmd.byte_patches = {"0x0=4142"}; // overwrite first two bytes
    auto r = cmd.run(ctx);
    REQUIRE(r);
    const auto patched = src.string() + ".patched";
    REQUIRE(std::filesystem::exists(patched));
    std::ifstream in(patched, std::ios::binary);
    std::vector<char> got((std::istreambuf_iterator<char>(in)), {});
    REQUIRE(got.size() == 16);
    REQUIRE(static_cast<unsigned char>(got[0]) == 0x41);
    REQUIRE(static_cast<unsigned char>(got[1]) == 0x42);
    REQUIRE(static_cast<unsigned char>(got[2]) == 0x41); // unchanged
    std::filesystem::remove_all(d);
}

TEST_CASE("PatchCommand NOP patch writes 0x90 bytes", "[patch][command]") {
    abcpwn::core::Context ctx;
    const auto d = tmp_dir();
    const auto src = d / "target.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out.write(std::string(8, 'A').data(), 8);
    }
    abcpwn::commands::diffpatch::PatchCommand cmd;
    cmd.target = src.string();
    cmd.nop_patches = {"2:3"};
    auto r = cmd.run(ctx);
    REQUIRE(r);
    std::ifstream in(src.string() + ".patched", std::ios::binary);
    std::vector<char> got((std::istreambuf_iterator<char>(in)), {});
    REQUIRE(got.size() == 8);
    REQUIRE(static_cast<unsigned char>(got[1]) == 0x41);
    REQUIRE(static_cast<unsigned char>(got[2]) == 0x90);
    REQUIRE(static_cast<unsigned char>(got[3]) == 0x90);
    REQUIRE(static_cast<unsigned char>(got[4]) == 0x90);
    REQUIRE(static_cast<unsigned char>(got[5]) == 0x41);
    std::filesystem::remove_all(d);
}

TEST_CASE("PatchCommand byte patch beyond EOF is InvalidInput", "[patch][command]") {
    abcpwn::core::Context ctx;
    const auto d = tmp_dir();
    const auto src = d / "target.bin";
    {
        std::ofstream out(src, std::ios::binary);
        out.write("AAAA", 4);
    }
    abcpwn::commands::diffpatch::PatchCommand cmd;
    cmd.target = src.string();
    cmd.byte_patches = {"0x10=4142"};
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::InvalidInput);
    std::filesystem::remove_all(d);
}
