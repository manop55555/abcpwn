// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/pack.hpp"

#include <CLI/CLI.hpp>

#include <string>

namespace abcpwn::commands {

void PackCommand::setup(CLI::App& app) {
    app.add_option("value", value, "Integer value to pack")->required();
    app.add_option("-w,--width", width, "Width in bytes: 1, 2, 4, or 8 (default 8)");
    app.add_flag("--be", big_endian, "Use big-endian byte order");
}

core::Result<core::CommandResult> PackCommand::run(const core::Context& /*ctx*/) {
    using encoding::Endian;
    auto bytes = encoding::pack(
        value, width, big_endian ? Endian::Big : Endian::Little);
    if (!bytes) {
        return core::err(bytes.error());
    }
    core::CommandResult res;
    res.raw_lines.push_back(encoding::hex_encode(*bytes));
    return res;
}

void UnpackCommand::setup(CLI::App& app) {
    app.add_option("hex", hex_input, "Hex string to unpack")->required();
    app.add_flag("--be", big_endian, "Use big-endian byte order");
}

core::Result<core::CommandResult> UnpackCommand::run(const core::Context& /*ctx*/) {
    using encoding::Endian;
    auto bytes = encoding::hex_decode(hex_input);
    if (!bytes) {
        return core::err(bytes.error());
    }
    auto val = encoding::unpack(*bytes, big_endian ? Endian::Big : Endian::Little);
    if (!val) {
        return core::err(val.error());
    }
    core::CommandResult res;
    res.raw_lines.push_back(std::to_string(*val));
    return res;
}

}  // namespace abcpwn::commands
