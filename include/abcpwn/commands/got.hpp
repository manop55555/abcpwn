// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"

#include <cstdint>
#include <string>

namespace abcpwn::commands::got {

class GotCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "got"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "list GOT entries and build overwrite payloads";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    bool        list{true};
    std::string overwrite{};        // "<symbol>=<value-hex>"
    std::string symbol_filter{};
};

}  // namespace abcpwn::commands::got
