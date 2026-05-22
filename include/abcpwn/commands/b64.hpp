// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/command.hpp"

#include <string>

namespace abcpwn::commands {

class B64Command : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "b64"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "encode or decode base64";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string input{};
    bool        decode{false};
};

}  // namespace abcpwn::commands
