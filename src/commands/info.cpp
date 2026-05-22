// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/info.hpp"

#include <cstdint>
#include <sstream>
#include <string>

#include <CLI/CLI.hpp>

#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands {

namespace {

std::string hex_addr(std::uint64_t v) {
    std::ostringstream os;
    os << "0x" << std::hex << v;
    return os.str();
}

const char* relro_text(formats::Mitigations::RelroLevel r) noexcept {
    switch (r) {
    case formats::Mitigations::RelroLevel::Full:
        return "full";
    case formats::Mitigations::RelroLevel::Partial:
        return "partial";
    case formats::Mitigations::RelroLevel::None:
        return "none";
    }
    return "none";
}

} // namespace

void InfoCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to inspect")->required();
    app.add_option("-a,--arch", arch_override, "Override auto-detected arch");
    app.add_flag("--no-strategy", no_strategy, "Skip strategy suggestion");
}

core::Result<core::CommandResult> InfoCommand::run(const core::Context& /*ctx*/) {
    auto loaded = formats::load(target);
    if (!loaded) {
        return core::err(loaded.error());
    }
    const auto& info = loaded->info();

    core::CommandResult res;

    {
        core::Section s;
        s.title = "Architecture";
        s.findings.emplace_back(
            core::Severity::Info, "format", std::string(formats::format_name(info.format)));
        s.findings.emplace_back(
            core::Severity::Info, "arch", arch_override.empty() ? info.arch : arch_override);
        s.findings.emplace_back(
            core::Severity::Info, "endian", std::string(formats::endian_name(info.endian)));
        s.findings.emplace_back(
            core::Severity::Info, "bits", std::to_string(static_cast<unsigned>(info.bits)));
        if (info.entry_point != 0) {
            s.findings.emplace_back(core::Severity::Info, "entry", hex_addr(info.entry_point));
        }
        res.sections.push_back(std::move(s));
    }

    {
        core::Section s;
        s.title = "Mitigations";
        const auto& m = info.mitigations;
        const auto sev_ok = m.relro == formats::Mitigations::RelroLevel::Full ? core::Severity::Info
                                                                              : core::Severity::Low;
        s.findings.emplace_back(sev_ok, "RELRO", relro_text(m.relro));
        s.findings.emplace_back(m.canary ? core::Severity::Info : core::Severity::Medium,
                                "Canary",
                                m.canary ? "yes" : "no");
        s.findings.emplace_back(
            m.nx ? core::Severity::Info : core::Severity::High, "NX", m.nx ? "yes" : "no");
        s.findings.emplace_back(
            m.pie ? core::Severity::Info : core::Severity::Medium, "PIE", m.pie ? "yes" : "no");
        s.findings.emplace_back(m.fortify ? core::Severity::Info : core::Severity::Low,
                                "Fortify",
                                m.fortify ? "yes" : "no");
        if (m.rpath || m.runpath) {
            s.findings.emplace_back(
                core::Severity::Medium, "RPATH", m.rpath ? "set (DT_RPATH)" : "set (DT_RUNPATH)");
        }
        s.findings.emplace_back(core::Severity::Info, "Stripped", m.stripped ? "yes" : "no");
        res.sections.push_back(std::move(s));
    }

    {
        core::Section s;
        s.title = "Symbols";
        s.findings.emplace_back(
            core::Severity::Info, "dynamic imports", std::to_string(info.dynamic_imports.size()));
        if (!info.dangerous_functions.empty()) {
            std::string list;
            for (std::size_t i = 0; i < info.dangerous_functions.size(); ++i) {
                if (i != 0)
                    list.append(", ");
                list.append(info.dangerous_functions[i]);
            }
            s.findings.emplace_back(core::Severity::High, "dangerous", list);
        }
        res.sections.push_back(std::move(s));
    }

    if (!no_strategy) {
        core::Section s;
        s.title = "Strategy hint";
        std::string hint;
        if (!info.dangerous_functions.empty()) {
            hint = "target imports dangerous functions; classic stack overflow / ret2libc viable.";
        } else if (info.mitigations.pie && info.mitigations.nx) {
            hint = "PIE + NX + (no obvious dangerous import); leak first, then ROP.";
        } else {
            hint = "no obvious entry; start with strings + disasm.";
        }
        s.findings.emplace_back(core::Severity::Info, "suggestion", hint);
        res.sections.push_back(std::move(s));
    }

    return res;
}

} // namespace abcpwn::commands
