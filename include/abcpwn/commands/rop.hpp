// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

class RopCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "rop";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "build a ROP chain for a given strategy";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::int64_t syscall_number{-1};
    std::vector<std::uint64_t> syscall_args{};
};

} // namespace abcpwn::commands
