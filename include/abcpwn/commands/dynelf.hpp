// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::commands::dynelf {

struct LeakPair {
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes{};
};

// Parse a single "addr=hex" leak specification.
[[nodiscard]] core::Result<LeakPair> parse_leak_arg(std::string_view s);

class DynelfCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "dynelf";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "parse leak pairs into a structured form for downstream tools";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::vector<std::string> leaks{};
};

} // namespace abcpwn::commands::dynelf
