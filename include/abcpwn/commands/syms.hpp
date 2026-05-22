// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"

#include <string>

namespace abcpwn::commands {

class SymsCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "syms"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "list symbols (dynamic/static/imports/exports)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    bool        dangerous_only{false};
    std::string filter{};
};

}  // namespace abcpwn::commands
