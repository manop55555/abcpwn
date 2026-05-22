// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/command.hpp"

#include <string>

namespace abcpwn::commands {

class ConstgrepCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "constgrep"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "search compiled-in constants (mmap, signals, auxv, ...)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string query{};
    std::string category{};
};

}  // namespace abcpwn::commands
