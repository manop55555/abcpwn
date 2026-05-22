// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::diffpatch {

class PatchCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "patch";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "apply byte / NOP / asm patches to a binary";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::vector<std::string> byte_patches{}; // offset=hex (repeatable)
    std::vector<std::string> nop_patches{};  // offset:count (repeatable)
    bool in_place{false};
    bool backup{true};
};

} // namespace abcpwn::commands::diffpatch
