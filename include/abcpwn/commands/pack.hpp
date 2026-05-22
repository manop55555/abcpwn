// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/command.hpp"

#include <cstdint>
#include <string>

namespace abcpwn::commands {

// `pack`: integer literal -> raw bytes via abcpwn::commands::encoding::pack.
class PackCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "pack"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "pack an integer into raw bytes (endian + width)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    // Public so the dispatcher (step 20) or tests can populate fields.
    std::uint64_t value{0};
    unsigned      width{8};
    bool          big_endian{false};
};

// `unpack`: raw bytes -> integer literal.
class UnpackCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "unpack"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "unpack raw bytes into an integer";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    // Hex string input ("DEADBEEF") is the most ergonomic CLI form.
    std::string hex_input{};
    bool        big_endian{false};
};

}  // namespace abcpwn::commands
