// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/got.hpp"

#include "abcpwn/formats/binary_loader.hpp"

#include <LIEF/LIEF.hpp>

#include <CLI/CLI.hpp>

#include <charconv>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

namespace abcpwn::commands::got {

namespace {

[[nodiscard]] std::optional<std::uint64_t> parse_hex(std::string_view s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
    }
    std::uint64_t v = 0;
    const auto* e = s.data() + s.size();
    const auto r = std::from_chars(s.data(), e, v, 16);
    if (r.ec != std::errc{} || r.ptr != e) {
        return std::nullopt;
    }
    return v;
}

struct GotEntry {
    std::string    symbol;
    std::uint64_t  got_address{0};
};

std::vector<GotEntry> collect_got(const LIEF::ELF::Binary& elf) {
    std::vector<GotEntry> out;
    for (const auto& reloc : elf.pltgot_relocations()) {
        if (!reloc.has_symbol()) continue;
        const auto* sym = reloc.symbol();
        if (sym == nullptr || sym->name().empty()) continue;
        out.push_back({sym->name(), reloc.address()});
    }
    return out;
}

}  // namespace

void GotCommand::setup(CLI::App& app) {
    app.add_option("target", target, "ELF binary to inspect")->required();
    app.add_flag("--list", list, "List all GOT entries (default)");
    app.add_option("--overwrite", overwrite,
        "Build overwrite payload: <symbol>=<value-hex>");
    app.add_option("--symbol", symbol_filter,
        "Show only the GOT entry for this symbol");
}

core::Result<core::CommandResult> GotCommand::run(const core::Context& /*ctx*/) {
    auto loaded = formats::load(target);
    if (!loaded) {
        return core::err(loaded.error());
    }
    const auto* elf = dynamic_cast<const LIEF::ELF::Binary*>(loaded->binary());
    if (elf == nullptr) {
        return core::err(core::ErrorCode::Unsupported,
            "got: only ELF binaries are supported");
    }

    const auto entries = collect_got(*elf);

    if (!overwrite.empty()) {
        const auto eq = overwrite.find('=');
        if (eq == std::string::npos) {
            return core::err(core::ErrorCode::UsageError,
                "got: --overwrite expects <symbol>=<value-hex>");
        }
        const std::string sym = overwrite.substr(0, eq);
        const auto value = parse_hex(overwrite.substr(eq + 1));
        if (!value) {
            return core::err(core::ErrorCode::InvalidInput,
                "got: --overwrite value must be hex");
        }
        std::optional<std::uint64_t> got_addr;
        for (const auto& e : entries) {
            if (e.symbol == sym) {
                got_addr = e.got_address;
                break;
            }
        }
        if (!got_addr) {
            return core::err(core::ErrorCode::NotFound,
                "got: no GOT entry for symbol '" + sym + "'");
        }
        char addr_buf[32];
        std::snprintf(addr_buf, sizeof addr_buf, "0x%lx",
            static_cast<unsigned long>(*got_addr));
        char val_buf[32];
        std::snprintf(val_buf, sizeof val_buf, "0x%lx",
            static_cast<unsigned long>(*value));
        core::CommandResult res;
        auto& sec = res.sections.emplace_back();
        sec.title = "GOT overwrite";
        sec.findings.emplace_back(core::Severity::Info, "symbol",  sym);
        sec.findings.emplace_back(core::Severity::Info, "GOT addr", addr_buf);
        sec.findings.emplace_back(core::Severity::Info, "value",    val_buf);
        sec.findings.emplace_back(core::Severity::Info, "primitive",
            "write " + std::string(val_buf) + " to " + std::string(addr_buf));
        return res;
    }

    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "GOT entries";
    for (const auto& e : entries) {
        if (!symbol_filter.empty() && e.symbol != symbol_filter) continue;
        char buf[32];
        std::snprintf(buf, sizeof buf, "0x%lx",
            static_cast<unsigned long>(e.got_address));
        sec.findings.emplace_back(core::Severity::Info, e.symbol, buf);
    }
    if (sec.findings.empty()) {
        sec.findings.emplace_back(core::Severity::Info, "(no GOT entries)",
            symbol_filter.empty() ? "binary has no PLT/GOT relocations"
                                  : "no entry for symbol '" + symbol_filter + "'");
    }
    res.summary = std::to_string(entries.size()) + " GOT entries";
    return res;
}

}  // namespace abcpwn::commands::got
