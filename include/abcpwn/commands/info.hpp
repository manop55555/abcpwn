// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

class InfoCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "info";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "show mitigations, arch, symbols, libc hint";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::string arch_override{};
    bool no_strategy{false};
};

} // namespace abcpwn::commands
