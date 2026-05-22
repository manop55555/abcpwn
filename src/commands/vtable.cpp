// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/vtable.hpp"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands::vtable {

namespace {

// Itanium C++ ABI vtable symbol prefix is `_ZTV`. The associated
// type_info object lives at `_ZTI`, and the typeinfo name at `_ZTS`.
[[nodiscard]] bool is_vtable_symbol(std::string_view name) noexcept {
    return name.starts_with("_ZTV");
}

std::string hex_str(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%lx", static_cast<unsigned long>(v));
    return std::string(b);
}

} // namespace

void VtableCommand::setup(CLI::App& app) {
    app.add_option("target", target, "ELF binary to inspect")->required();
    app.add_flag("--list", list, "List all C++ vtable symbols (Itanium ABI)");
    app.add_option(
        "--analyze", analyze_addr, "Identify the class whose vtable lives at this address (hex)");
    app.add_option("--hijack", hijack_vtable, "Existing vtable address to hijack (hex)");
    app.add_option("--method-idx",
                   hijack_method_idx,
                   "0-based method-table index to overwrite under --hijack");
    app.add_option(
        "--hijack-target", hijack_target, "Address to install at the chosen method slot (hex)");
}

core::Result<core::CommandResult> VtableCommand::run(const core::Context& /*ctx*/) {
    auto loaded = formats::load(target);
    if (!loaded) {
        return core::err(loaded.error());
    }
    const auto* elf = dynamic_cast<const LIEF::ELF::Binary*>(loaded->binary());
    if (elf == nullptr) {
        return core::err(core::ErrorCode::Unsupported, "vtable: only ELF binaries are supported");
    }

    // Collect every Itanium-ABI vtable symbol from dynsym + the
    // symtab section (when available). vtables typically land as
    // either OBJECT-type symbols pointing at a .rodata / .data.rel.ro
    // entry, or as defined symbols emitted by the C++ frontend.
    struct VtableSym {
        std::string name;
        std::uint64_t address;
        std::uint64_t size;
    };
    std::vector<VtableSym> vtables;

    auto absorb = [&](const auto& sym_iter) {
        for (const auto& sym : sym_iter) {
            const auto n = sym.name();
            if (is_vtable_symbol(n) && sym.value() != 0) {
                vtables.push_back({n, sym.value(), sym.size()});
            }
        }
    };
    absorb(elf->dynamic_symbols());
    absorb(elf->symtab_symbols());

    if (list) {
        core::CommandResult res;
        auto& sec = res.sections.emplace_back();
        sec.title = "C++ vtables (Itanium ABI)";
        for (const auto& v : vtables) {
            sec.findings.emplace_back(core::Severity::Info,
                                      v.name,
                                      hex_str(v.address) + "  size=" + std::to_string(v.size));
        }
        if (vtables.empty()) {
            sec.findings.emplace_back(core::Severity::Info,
                                      "(none)",
                                      "no _ZTV* symbols visible (stripped or not C++ Itanium ABI)");
        }
        res.summary = std::to_string(vtables.size()) + " vtables";
        return res;
    }

    if (analyze_addr != 0) {
        core::CommandResult res;
        auto& sec = res.sections.emplace_back();
        sec.title = "vtable analysis";
        const VtableSym* hit = nullptr;
        for (const auto& v : vtables) {
            if (v.address == analyze_addr) {
                hit = &v;
                break;
            }
        }
        if (hit != nullptr) {
            sec.findings.emplace_back(core::Severity::Info, "matched", hit->name);
            sec.findings.emplace_back(core::Severity::Info,
                                      "size",
                                      std::to_string(hit->size) + " bytes ("
                                          + std::to_string(hit->size / 8) + " slots, x86_64)");
        } else {
            sec.findings.emplace_back(core::Severity::Info,
                                      "no match",
                                      "address " + hex_str(analyze_addr)
                                          + " does not match any visible _ZTV* symbol");
        }
        return res;
    }

    if (hijack_vtable != 0) {
        if (hijack_method_idx < 0) {
            return core::err(core::ErrorCode::UsageError,
                             "vtable: --hijack requires --method-idx N (0-based)");
        }
        if (hijack_target == 0) {
            return core::err(core::ErrorCode::UsageError,
                             "vtable: --hijack requires --hijack-target ADDR");
        }
        core::CommandResult res;
        auto& sec = res.sections.emplace_back();
        sec.title = "vtable hijack primitive";
        // Itanium ABI vtable layout: at vtable_address-0x10 lives the
        // RTTI pointer + offset-to-top; method 0 is at vtable_address,
        // method 1 at +0x8, etc. (x86_64).
        const std::uint64_t slot_va =
            hijack_vtable + static_cast<std::uint64_t>(hijack_method_idx) * 8U;
        sec.findings.emplace_back(core::Severity::Info, "vtable", hex_str(hijack_vtable));
        sec.findings.emplace_back(
            core::Severity::Info, "method idx", std::to_string(hijack_method_idx));
        sec.findings.emplace_back(core::Severity::Info, "slot to overwrite", hex_str(slot_va));
        sec.findings.emplace_back(core::Severity::Info, "value to write", hex_str(hijack_target));
        sec.findings.emplace_back(core::Severity::Info,
                                  "primitive",
                                  "write " + hex_str(hijack_target) + " to " + hex_str(slot_va));
        return res;
    }

    return core::err(core::ErrorCode::UsageError,
                     "vtable: pick one of --list, --analyze, --hijack");
}

} // namespace abcpwn::commands::vtable
