// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::tmpl {

// Render an exploit-skeleton pwntools script for the given strategy
// against the given binary. The string is plain text suitable for
// `--output solve.py`.
[[nodiscard]] std::string render_template(std::string_view strategy, std::string_view binary_path);

class TemplateCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "template";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "emit a pwntools exploit skeleton for a strategy";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string strategy{"ret2libc"};
    std::string binary_path{};
    std::string output_path{};
};

} // namespace abcpwn::commands::tmpl
