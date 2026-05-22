// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/xor_cmd.hpp"

#include <string>

#include <CLI/CLI.hpp>

namespace abcpwn::commands {

void XorCommand::setup(CLI::App& app) {
    app.add_option("input", input_hex, "Hex bytes to XOR")->required();
    app.add_option("--key", key_hex, "Hex bytes of the key")->required();
    app.add_flag("--raw", emit_hex, "Emit raw bytes instead of hex (toggles off hex)");
}

core::Result<core::CommandResult> XorCommand::run(const core::Context& /*ctx*/) {
    auto data = encoding::hex_decode(input_hex);
    if (!data) {
        return core::err(data.error());
    }
    auto key = encoding::hex_decode(key_hex);
    if (!key) {
        return core::err(key.error());
    }
    auto out = encoding::xor_with_key(*data, *key);
    core::CommandResult res;
    if (emit_hex) {
        res.raw_lines.push_back(encoding::hex_encode(out));
    } else {
        res.raw_lines.emplace_back(reinterpret_cast<const char*>(out.data()), out.size());
    }
    return res;
}

} // namespace abcpwn::commands
