// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/ret2dl.hpp"

#include <cstdint>
#include <cstdio>
#include <string>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands::ret2dl {

void Ret2dlCommand::setup(CLI::App& app) {
    app.add_option("target", target, "ELF binary to analyze")->required();
    app.add_option("symbol", symbol, "Symbol to resolve (e.g., system, execve, gets)")->required();
    app.add_option("--base", base, "Writable region base (hex)");
    app.add_option("--bad-chars", bad_chars_hex, "Hex bytes to avoid");
}

core::Result<core::CommandResult> Ret2dlCommand::run(const core::Context& ctx) {
    auto loaded = formats::load(target, formats::LoadOptions{ctx.limits.max_file_bytes, true});
    if (!loaded) {
        return core::err(loaded.error());
    }
    auto* elf = dynamic_cast<const LIEF::ELF::Binary*>(loaded->binary());
    if (elf == nullptr) {
        return core::err(core::ErrorCode::Unsupported, "ret2dl: only ELF binaries are supported");
    }

    // Locate plt / plt.got / dynamic / dynstr / dynsym section
    // virtual addresses so callers can build the fake reloc/symbol
    // structures themselves. Full payload synthesis (which fabricates
    // Elf64_Rela + Elf64_Sym entries pointing at a writable .bss area)
    // is deferred to a later milestone -- it requires choosing a
    // writable region, computing reloc indices, and is highly target-
    // specific. The v0.1 surface reports the structural offsets the
    // user needs to construct that payload by hand or with pwntools'
    // ret2dl helper.
    std::uint64_t plt_va = 0;
    std::uint64_t dynsym_va = 0;
    std::uint64_t dynstr_va = 0;
    std::uint64_t rela_plt_va = 0;
    for (const auto& sec : elf->sections()) {
        const auto name = sec.name();
        if (name == ".plt")
            plt_va = sec.virtual_address();
        if (name == ".dynsym")
            dynsym_va = sec.virtual_address();
        if (name == ".dynstr")
            dynstr_va = sec.virtual_address();
        if (name == ".rela.plt")
            rela_plt_va = sec.virtual_address();
        if (name == ".rel.plt" && rela_plt_va == 0)
            rela_plt_va = sec.virtual_address();
    }
    if (plt_va == 0 || dynsym_va == 0) {
        return core::err(core::ErrorCode::NotFound,
                         "ret2dl: target has no .plt / .dynsym (not a dynamically linked ELF?)");
    }

    // Try to find the symbol's PLT trampoline by name (this gives the
    // caller the "call this address with the fake reloc index" entry
    // point they need).
    std::optional<std::uint64_t> sym_va;
    for (const auto& sym : elf->dynamic_symbols()) {
        if (sym.name() == symbol) {
            sym_va = sym.value();
            break;
        }
    }

    auto hex = [](std::uint64_t v) {
        char b[32];
        std::snprintf(b, sizeof b, "0x%lx", static_cast<unsigned long>(v));
        return std::string(b);
    };

    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "ret2dlresolve structural offsets";
    sec.findings.emplace_back(core::Severity::Info, ".plt", hex(plt_va));
    sec.findings.emplace_back(core::Severity::Info, ".dynsym", hex(dynsym_va));
    sec.findings.emplace_back(
        core::Severity::Info, ".dynstr", dynstr_va ? hex(dynstr_va) : std::string("(not found)"));
    sec.findings.emplace_back(core::Severity::Info,
                              ".rel(a).plt",
                              rela_plt_va ? hex(rela_plt_va) : std::string("(not found)"));
    if (sym_va) {
        sec.findings.emplace_back(
            core::Severity::Info, std::string("dynamic symbol ") + symbol, hex(*sym_va));
    } else {
        sec.findings.emplace_back(
            core::Severity::Medium,
            std::string("dynamic symbol ") + symbol,
            "not in .dynsym (cannot be resolved via the existing PLT trampoline)");
    }
    if (base != 0) {
        sec.findings.emplace_back(core::Severity::Info, "writable base", hex(base));
    }
    sec.findings.emplace_back(core::Severity::Info,
                              "note",
                              "v0.1 reports structural offsets; full Elf64_Rela + Elf64_Sym "
                              "fabrication is deferred to a later milestone");
    (void) bad_chars_hex; // accepted for forward compat
    return res;
}

} // namespace abcpwn::commands::ret2dl
