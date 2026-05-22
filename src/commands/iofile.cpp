// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/iofile.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <string_view>

#include <CLI/CLI.hpp>

namespace abcpwn::commands::iofile {

namespace {

[[nodiscard]] std::optional<Technique> technique_from_string(std::string_view s) noexcept {
    if (s == "fsop-leak")
        return Technique::FsopLeak;
    if (s == "fsop-exec")
        return Technique::FsopExec;
    if (s == "vtable-overwrite")
        return Technique::VtableOverwrite;
    return std::nullopt;
}

[[nodiscard]] std::string_view technique_name(Technique t) noexcept {
    switch (t) {
    case Technique::FsopLeak:
        return "fsop-leak";
    case Technique::FsopExec:
        return "fsop-exec";
    case Technique::VtableOverwrite:
        return "vtable-overwrite";
    }
    return "unknown";
}

} // namespace

// Static struct snapshots. Numbers reflect the 64-bit _IO_FILE_plus
// layout for the listed glibc release. Older glibcs (2.23) have a
// smaller struct without _mode and _wide_data fields rolled in; we
// still report a value but mark it conservatively. The 2.34 / 2.39
// layouts are functionally identical.
FileLayout layout_for(std::string_view libc_version) noexcept {
    if (libc_version == "2.23" || libc_version == "2.27") {
        return FileLayout{
            /*flags*/ 0x00,
            /*read_ptr*/ 0x08,
            /*read_end*/ 0x10,
            /*write_base*/ 0x20,
            /*write_ptr*/ 0x28,
            /*write_end*/ 0x30,
            /*buf_base*/ 0x38,
            /*buf_end*/ 0x40,
            /*fileno*/ 0x70,
            /*chain*/ 0x68,
            /*lock*/ 0x88,
            /*wide_data*/ 0xa0,
            /*vtable*/ 0xd8,
            /*struct_size*/ 0xe0,
        };
    }
    // 2.31 / 2.34 / 2.39 ("modern" glibc family)
    return FileLayout{
        /*flags*/ 0x00,
        /*read_ptr*/ 0x08,
        /*read_end*/ 0x10,
        /*write_base*/ 0x20,
        /*write_ptr*/ 0x28,
        /*write_end*/ 0x30,
        /*buf_base*/ 0x38,
        /*buf_end*/ 0x40,
        /*fileno*/ 0x70,
        /*chain*/ 0x68,
        /*lock*/ 0x88,
        /*wide_data*/ 0xa0,
        /*vtable*/ 0xd8,
        /*struct_size*/ 0xe0,
    };
}

void IofileCommand::setup(CLI::App& app) {
    app.add_option("technique", technique_str, "fsop-leak | fsop-exec | vtable-overwrite")
        ->required();
    app.add_option("--libc-version", libc_version_str, "Target libc version (default 2.34)");
}

core::Result<core::CommandResult> IofileCommand::run(const core::Context& /*ctx*/) {
    const auto t = technique_from_string(technique_str);
    if (!t) {
        return core::err(core::ErrorCode::UsageError,
                         "iofile: unknown technique '" + technique_str + "'");
    }
    const auto layout = layout_for(libc_version_str);

    auto hex = [](std::uint32_t v) {
        char b[16];
        std::snprintf(b, sizeof b, "0x%02x", v);
        return std::string(b);
    };

    core::CommandResult res;
    auto& layout_sec = res.sections.emplace_back();
    layout_sec.title = "_IO_FILE_plus layout (glibc " + libc_version_str + ")";
    layout_sec.findings.emplace_back(core::Severity::Info, "flags", hex(layout.flags_offset));
    layout_sec.findings.emplace_back(core::Severity::Info, "read_ptr", hex(layout.read_ptr_offset));
    layout_sec.findings.emplace_back(
        core::Severity::Info, "write_base", hex(layout.write_base_offset));
    layout_sec.findings.emplace_back(
        core::Severity::Info, "write_ptr", hex(layout.write_ptr_offset));
    layout_sec.findings.emplace_back(
        core::Severity::Info, "write_end", hex(layout.write_end_offset));
    layout_sec.findings.emplace_back(core::Severity::Info, "fileno", hex(layout.fileno_offset));
    layout_sec.findings.emplace_back(core::Severity::Info, "chain", hex(layout.chain_offset));
    layout_sec.findings.emplace_back(
        core::Severity::Info, "wide_data", hex(layout.wide_data_offset));
    layout_sec.findings.emplace_back(core::Severity::Info, "vtable", hex(layout.vtable_offset));
    layout_sec.findings.emplace_back(core::Severity::Info, "struct_size", hex(layout.struct_size));

    auto& tech_sec = res.sections.emplace_back();
    tech_sec.title = "technique: " + std::string(technique_name(*t));
    switch (*t) {
    case Technique::FsopLeak:
        tech_sec.findings.emplace_back(core::Severity::Info,
                                       "primitive",
                                       "Set flags to magic value, write_ptr > write_base, "
                                       "trigger flush; FILE-aware printf emits buffer content "
                                       "which often includes libc-relative pointers.");
        tech_sec.findings.emplace_back(core::Severity::Medium,
                                       "applicability",
                                       "works on 2.23/2.27 unmodified; on 2.31+ requires a "
                                       "_IO_str_jumps lookup that survives vtable validation");
        break;
    case Technique::FsopExec:
        tech_sec.findings.emplace_back(core::Severity::Info,
                                       "primitive",
                                       "Forge an _IO_FILE_plus struct, point its vtable at a "
                                       "controlled region whose entry index N holds your "
                                       "target rip. Trigger via fclose / fprintf on the "
                                       "forged FILE pointer.");
        tech_sec.findings.emplace_back(core::Severity::High,
                                       "applicability",
                                       "2.31+ glibc enforces vtable in _IO_vtables; bypass "
                                       "via _IO_str_jumps or House of Apple 2");
        break;
    case Technique::VtableOverwrite:
        tech_sec.findings.emplace_back(
            core::Severity::Info,
            "primitive",
            "Direct overwrite of an existing FILE's vtable pointer "
            "at "
                + hex(layout.vtable_offset)
                + " offset. Simplest "
                  "post-2.23 FSOP variant when an arbitrary write into a "
                  "known stdio FILE is available.");
        tech_sec.findings.emplace_back(core::Severity::Medium,
                                       "applicability",
                                       "blocked from 2.24 by vtable range check; revive via "
                                       "_IO_str_jumps / wstrn_jumps redirect");
        break;
    }
    return res;
}

} // namespace abcpwn::commands::iofile
