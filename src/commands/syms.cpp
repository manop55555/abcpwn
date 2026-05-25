// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/syms.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <regex>
#include <string>
#include <utility>

#include <CLI/CLI.hpp>
#include <LIEF/ELF/Binary.hpp>
#include <LIEF/ELF/Symbol.hpp>

#include "abcpwn/core/validate.hpp"
#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands {

namespace {

std::string hex_addr(std::uint64_t v) {
    char buf[20];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

} // namespace

void SymsCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to inspect")->required();
    app.add_flag("--dangerous", dangerous_only, "Only show dangerous functions");
    app.add_option("--filter", filter, "Regex applied to symbol names");
    app.add_option("--source", source, "Symbol table: dynamic | static | all (default all)");
}

core::Result<core::CommandResult> SymsCommand::run(const core::Context& ctx) {
    if (auto e = core::validate_choice("syms: unknown source",
                                       source,
                                       {"dynamic", "static", "all"},
                                       core::ErrorCode::UsageError)) {
        return core::err(e->code, std::move(e->message));
    }

    auto loaded = formats::load(target, formats::LoadOptions{ctx.limits.max_file_bytes, true});
    if (!loaded) {
        return core::err(loaded.error());
    }
    const auto& info = loaded->info();

    std::optional<std::regex> rx;
    if (!filter.empty()) {
        try {
            rx.emplace(filter);
        } catch (const std::regex_error& e) {
            return core::err(core::ErrorCode::InvalidInput,
                             std::string("syms: bad --filter regex: ") + e.what());
        }
    }
    const auto matches = [&](const std::string& n) { return !rx || std::regex_search(n, *rx); };

    core::CommandResult res;

    // --dangerous keeps its existing behavior: the curated dangerous-import
    // list by name. --source governs the full symbol listing below.
    if (dangerous_only) {
        core::Section sec;
        sec.title = "Dangerous functions";
        for (const auto& sym : info.dangerous_functions) {
            if (matches(sym)) {
                sec.findings.emplace_back(core::Severity::High, sym);
            }
        }
        if (sec.findings.empty()) {
            sec.findings.emplace_back(core::Severity::Info, "(no symbols matched)");
        }
        res.sections.push_back(std::move(sec));
        return res;
    }

    const bool want_dyn = source == "dynamic" || source == "all";
    const bool want_static = source == "static" || source == "all";

    core::Section sec;
    sec.title = "Symbols";

    const auto add_sym = [&](const std::string& name, std::uint64_t addr, const char* src) {
        if (name.empty() || !matches(name)) {
            return;
        }
        core::Finding f(core::Severity::Info, name, hex_addr(addr));
        f.offset = addr;
        f.extra["source"] = std::string(src);
        sec.findings.push_back(std::move(f));
    };

    // ELF: read .dynsym (dynamic) and/or .symtab (static), each carrying an
    // address. Local/static functions (e.g. a `win()` helper) live only in
    // .symtab, which the previous implementation never read.
    if (auto* elf = dynamic_cast<LIEF::ELF::Binary*>(loaded->binary())) {
        if (want_dyn) {
            for (const auto& s : elf->dynamic_symbols()) {
                add_sym(s.name(), s.value(), "dynamic");
            }
        }
        if (want_static) {
            for (const auto& s : elf->symtab_symbols()) {
                add_sym(s.name(), s.value(), "static");
            }
        }
    } else if (want_dyn) {
        // PE / Mach-O: fall back to the loader's name-only import list; static
        // symbols with addresses are an ELF-only feature in v0.1.
        for (const auto& name : info.dynamic_imports) {
            add_sym(name, 0, "dynamic");
        }
    }

    if (sec.findings.empty()) {
        sec.findings.emplace_back(core::Severity::Info, "(no symbols matched)");
    }
    res.sections.push_back(std::move(sec));
    return res;
}

} // namespace abcpwn::commands
