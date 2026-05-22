// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/hex.hpp"

#include <CLI/CLI.hpp>

#include <cstdint>
#include <span>
#include <string>

namespace abcpwn::commands {

void HexCommand::setup(CLI::App& app) {
    app.add_option("input", input, "String to hex-encode")->required();
    app.add_option("--delim", delim, "Delimiter between bytes (default: none)");
}

core::Result<core::CommandResult> HexCommand::run(const core::Context& /*ctx*/) {
    const std::span<const std::uint8_t> bytes{
        reinterpret_cast<const std::uint8_t*>(input.data()),
        input.size(),
    };
    core::CommandResult res;
    res.raw_lines.push_back(encoding::hex_encode(bytes, delim));
    return res;
}

void UnhexCommand::setup(CLI::App& app) {
    app.add_option("input", input, "Hex string to decode")->required();
}

core::Result<core::CommandResult> UnhexCommand::run(const core::Context& /*ctx*/) {
    auto bytes = encoding::hex_decode(input);
    if (!bytes) {
        return core::err(bytes.error());
    }
    core::CommandResult res;
    res.raw_lines.emplace_back(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    return res;
}

}  // namespace abcpwn::commands
