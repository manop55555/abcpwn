// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

class AsmCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "asm";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "assemble source text into raw bytes (requires Keystone)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string source{};
    std::string arch_name{"x86_64"};
    std::uint64_t base_address{0};
    bool big_endian{false};
    bool thumb{false};
    std::string format{"hex"}; // hex | raw | escaped | c
};

} // namespace abcpwn::commands
