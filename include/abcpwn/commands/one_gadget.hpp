// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"

#include <string>

namespace abcpwn::commands {

class OneGadgetCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "one-gadget"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "find execve(\"/bin/sh\", ...) one-gadget candidates in libc";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string libc{};
    bool        all{false};
};

}  // namespace abcpwn::commands
