// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::aslr_bypass {

class AslrBypassCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "aslr-bypass";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "ASLR / PIE bypass helpers (partial overwrite, brute force, canary)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    bool partial_overwrite{false};
    bool brute_force{false};
    bool canary_leak{false};
    std::uint32_t entropy_bits{28}; // typical 64-bit PIE has 28 bits of entropy
};

} // namespace abcpwn::commands::aslr_bypass
