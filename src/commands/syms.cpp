// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/syms.hpp"

#include "abcpwn/formats/binary_loader.hpp"

#include <CLI/CLI.hpp>

#include <algorithm>
#include <regex>
#include <string>

namespace abcpwn::commands {

void SymsCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to inspect")->required();
    app.add_flag("--dangerous", dangerous_only, "Only show dangerous functions");
    app.add_option("--filter", filter, "Regex applied to symbol names");
}

core::Result<core::CommandResult> SymsCommand::run(const core::Context& /*ctx*/) {
    auto loaded = formats::load(target);
    if (!loaded) {
        return core::err(loaded.error());
    }
    const auto& info = loaded->info();

    core::CommandResult res;
    core::Section sec;
    sec.title = "Dynamic imports";

    std::optional<std::regex> rx;
    if (!filter.empty()) {
        try {
            rx.emplace(filter);
        } catch (const std::regex_error& e) {
            return core::err(core::ErrorCode::InvalidInput,
                std::string("syms: bad --filter regex: ") + e.what());
        }
    }

    const auto& source = dangerous_only ? info.dangerous_functions : info.dynamic_imports;
    for (const auto& sym : source) {
        if (rx && !std::regex_search(sym, *rx)) continue;
        sec.findings.emplace_back(
            dangerous_only ? core::Severity::High : core::Severity::Info,
            sym);
    }
    if (sec.findings.empty()) {
        sec.findings.emplace_back(core::Severity::Info, "(no symbols matched)");
    }
    res.sections.push_back(std::move(sec));
    return res;
}

}  // namespace abcpwn::commands
