// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <string>

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

class XorCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "xor";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "xor bytes against a repeating key";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string input_hex{};
    std::string key_hex{};
    bool emit_hex{true};
};

} // namespace abcpwn::commands
