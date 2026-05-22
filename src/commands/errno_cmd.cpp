// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/errno_cmd.hpp"

#include <CLI/CLI.hpp>

#include <cctype>
#include <charconv>
#include <string>
#include <string_view>

namespace abcpwn::commands {

void ErrnoCommand::setup(CLI::App& app) {
    app.add_option("query", query,
        "errno number (e.g., 2) or name (e.g., ENOENT). Omit to list all.");
}

core::Result<core::CommandResult> ErrnoCommand::run(const core::Context& /*ctx*/) {
    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "errno";

    if (query.empty()) {
        for (const auto& e : encoding::errno_table()) {
            core::Finding f;
            f.title  = std::string(e.name);
            f.detail = std::to_string(e.number) + "  " + std::string(e.message);
            sec.findings.push_back(std::move(f));
        }
        return res;
    }

    const encoding::ErrnoEntry* hit = nullptr;
    const bool numeric = !query.empty()
        && (query[0] == '-' || std::isdigit(static_cast<unsigned char>(query[0])) != 0);
    if (numeric) {
        int n = 0;
        const auto* begin = query.data();
        const auto* end   = query.data() + query.size();
        const auto conv = std::from_chars(begin, end, n);
        if (conv.ec == std::errc{} && conv.ptr == end) {
            hit = encoding::errno_by_number(n);
        }
    } else {
        hit = encoding::errno_by_name(query);
    }

    if (hit == nullptr) {
        return core::err(core::ErrorCode::NotFound,
            "errno: '" + query + "' not in the project table");
    }

    core::Finding f;
    f.title  = std::string(hit->name);
    f.detail = std::to_string(hit->number) + "  " + std::string(hit->message);
    sec.findings.push_back(std::move(f));
    return res;
}

}  // namespace abcpwn::commands
