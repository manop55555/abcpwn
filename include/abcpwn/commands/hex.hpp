// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/command.hpp"

#include <string>

namespace abcpwn::commands {

class HexCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "hex"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "encode raw input as hex bytes";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string input{};
    std::string delim{};
};

class UnhexCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "unhex"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "decode hex bytes into raw output";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string input{};
};

}  // namespace abcpwn::commands
