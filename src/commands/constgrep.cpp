// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/constgrep.hpp"

#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

#include <CLI/CLI.hpp>

namespace abcpwn::commands {

void ConstgrepCommand::setup(CLI::App& app) {
    app.add_option("query", query, "Substring to search in constant names")->required();
    app.add_option("--category", category, "Restrict to a category (mmap, signal, auxv)");
}

core::Result<core::CommandResult> ConstgrepCommand::run(const core::Context& /*ctx*/) {
    const auto hits = encoding::constgrep_search(query, category);
    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "constants";
    for (const auto& c : hits) {
        core::Finding f;
        f.title = std::string(c.category) + "::" + std::string(c.name);
        std::ostringstream hex;
        hex << std::hex << std::uppercase << static_cast<std::uint64_t>(c.value);
        f.detail = std::to_string(c.value) + "  (0x" + hex.str() + ")";
        sec.findings.push_back(std::move(f));
    }
    if (hits.empty()) {
        return core::err(core::ErrorCode::NotFound,
                         "constgrep: no constants match '" + query + "'");
    }
    return res;
}

} // namespace abcpwn::commands
