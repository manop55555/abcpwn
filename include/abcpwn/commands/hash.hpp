// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands {

[[nodiscard]] std::string sha256_hex(std::span<const std::uint8_t> data);

class HashCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "hash"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "compute file hash (sha256 default)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::vector<std::string> targets{};
    std::string              algorithm{"sha256"};
};

}  // namespace abcpwn::commands
