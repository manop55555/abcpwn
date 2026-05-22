// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/safe_link.hpp"

#include <CLI/CLI.hpp>

#include <cstdio>
#include <string>

namespace abcpwn::commands::safe_link {

void SafeLinkCommand::setup(CLI::App& app) {
    app.add_option("value", ptr_or_encoded,
        "Pointer (when encoding) or encoded fd (when decoding)")
        ->required();
    app.add_option("pos", pos,
        "Position the value lives at (the chunk address holding the fd)")
        ->required();
    app.add_flag("--decode{false},--encode{true}", encode,
        "Default --encode; pass --decode to recover the original ptr");
}

core::Result<core::CommandResult> SafeLinkCommand::run(const core::Context& /*ctx*/) {
    if (pos == 0) {
        return core::err(core::ErrorCode::InvalidInput,
            "safe-link: pos must be non-zero (it is the chunk address)");
    }
    const auto out = encode
        ? safe_link_encode(ptr_or_encoded, pos)
        : safe_link_decode(ptr_or_encoded, pos);
    char buf[32];
    std::snprintf(buf, sizeof buf, "0x%lx", static_cast<unsigned long>(out));
    core::CommandResult res;
    res.raw_lines.emplace_back(buf);
    return res;
}

}  // namespace abcpwn::commands::safe_link
