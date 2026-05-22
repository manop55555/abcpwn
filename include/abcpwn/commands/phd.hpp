// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

// Free function used by both phd and any caller that wants the same
// hex-dump layout (`disasm` uses its own, this is the dedicated phd
// formatter).
[[nodiscard]] std::vector<std::string>
format_hex_dump(std::span<const std::uint8_t> data, std::uint64_t base_offset, std::size_t width);

class PhdCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "phd";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "pretty hex dump (offset, bytes, ASCII column)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    // Input may be either a path (input_file=true) or a literal hex
    // string. Length is capped to limit memory use.
    std::string input{};
    bool input_file{true};
    std::uint64_t offset{0};
    std::size_t length{0}; // 0 = all (subject to cap)
    std::size_t width{16};
};

} // namespace abcpwn::commands
