// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/iofile.hpp"
#include "abcpwn/commands/vtable.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/test_paths.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <string>

namespace {
std::filesystem::path fixture(std::string_view name) {
    return std::filesystem::path(abcpwn::test_paths::fixtures_dir) / "binaries" / std::string(name);
}
}  // namespace

// --- iofile ------------------------------------------------------------------

TEST_CASE("layout_for surfaces all named offsets on modern glibc", "[iofile]") {
    using namespace abcpwn::commands::iofile;
    const auto l = layout_for("2.34");
    REQUIRE(l.flags_offset      == 0x00);
    REQUIRE(l.write_ptr_offset  == 0x28);
    REQUIRE(l.fileno_offset     == 0x70);
    REQUIRE(l.vtable_offset     == 0xd8);
    REQUIRE(l.struct_size       == 0xe0);
}

TEST_CASE("layout_for returns the older layout for 2.23/2.27", "[iofile]") {
    using namespace abcpwn::commands::iofile;
    const auto l27 = layout_for("2.27");
    REQUIRE(l27.vtable_offset == 0xd8);
}

TEST_CASE("IofileCommand fsop-exec output names primitive + applicability", "[iofile][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::iofile::IofileCommand cmd;
    cmd.technique_str    = "fsop-exec";
    cmd.libc_version_str = "2.34";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE(r->sections.size() == 2);
    bool seen_primitive = false;
    bool seen_applicability = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "primitive")     seen_primitive = true;
            if (f.title == "applicability") seen_applicability = true;
        }
    }
    REQUIRE(seen_primitive);
    REQUIRE(seen_applicability);
}

TEST_CASE("IofileCommand vtable-overwrite reports the vtable offset", "[iofile][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::iofile::IofileCommand cmd;
    cmd.technique_str    = "vtable-overwrite";
    cmd.libc_version_str = "2.34";
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool mentions_d8 = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.detail.find("0xd8") != std::string::npos) mentions_d8 = true;
        }
    }
    REQUIRE(mentions_d8);
}

TEST_CASE("IofileCommand unknown technique is a usage error", "[iofile][command]") {
    abcpwn::core::Context ctx;
    abcpwn::commands::iofile::IofileCommand cmd;
    cmd.technique_str = "fsop-nonsense";
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

// --- vtable ------------------------------------------------------------------

TEST_CASE("VtableCommand --list runs cleanly on hello-hardened", "[vtable][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::vtable::VtableCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    cmd.list   = true;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    REQUIRE_FALSE(r->sections.empty());
    // The C fixture has no C++ vtables -- the command should still
    // succeed and report the "(none)" finding.
    bool saw_none = false;
    for (const auto& f : r->sections[0].findings) {
        if (f.title == "(none)") saw_none = true;
    }
    REQUIRE(saw_none);
}

TEST_CASE("VtableCommand --hijack computes the slot VA", "[vtable][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::vtable::VtableCommand cmd;
    cmd.target            = fixture("hello-hardened").string();
    cmd.hijack_vtable     = 0x400000;
    cmd.hijack_method_idx = 3;
    cmd.hijack_target     = 0xdeadbeef;
    auto r = cmd.run(ctx);
    REQUIRE(r);
    bool saw_slot = false;
    for (const auto& s : r->sections) {
        for (const auto& f : s.findings) {
            if (f.title == "slot to overwrite"
                && f.detail.find("0x400018") != std::string::npos)
            {
                saw_slot = true;
            }
        }
    }
    REQUIRE(saw_slot);
}

TEST_CASE("VtableCommand --hijack without method-idx is a usage error", "[vtable][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::vtable::VtableCommand cmd;
    cmd.target        = fixture("hello-hardened").string();
    cmd.hijack_vtable = 0x400000;
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}

TEST_CASE("VtableCommand without an action is a usage error", "[vtable][command]") {
    if (!std::filesystem::exists(fixture("hello-hardened"))) {
        SKIP("hello-hardened fixture not present");
    }
    abcpwn::core::Context ctx;
    abcpwn::commands::vtable::VtableCommand cmd;
    cmd.target = fixture("hello-hardened").string();
    auto r = cmd.run(ctx);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == abcpwn::core::ErrorCode::UsageError);
}
