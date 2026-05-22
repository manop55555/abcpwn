// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/b64.hpp"

#include <CLI/CLI.hpp>

#include <cstdint>
#include <span>
#include <string>

namespace abcpwn::commands {

void B64Command::setup(CLI::App& app) {
    app.add_option("input", input, "String to encode (or base64 to decode)")->required();
    app.add_flag("-d,--decode", decode, "Decode instead of encoding");
}

core::Result<core::CommandResult> B64Command::run(const core::Context& /*ctx*/) {
    core::CommandResult res;
    if (decode) {
        auto bytes = encoding::base64_decode(input);
        if (!bytes) {
            return core::err(bytes.error());
        }
        res.raw_lines.emplace_back(reinterpret_cast<const char*>(bytes->data()), bytes->size());
    } else {
        const std::span<const std::uint8_t> bytes{
            reinterpret_cast<const std::uint8_t*>(input.data()),
            input.size(),
        };
        res.raw_lines.push_back(encoding::base64_encode(bytes));
    }
    return res;
}

}  // namespace abcpwn::commands
