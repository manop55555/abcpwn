// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"

#include <cstdint>
#include <string>

namespace abcpwn::commands {

class DisasmCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "disasm"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "disassemble raw bytes with capstone";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    // Input: either a hex string (input_hex=true) or a file path.
    std::string   input{};
    bool          input_hex{true};
    std::string   arch_name{"x86_64"};
    std::uint64_t base_address{0};
    std::size_t   max_instructions{0};
    bool          big_endian{false};
    bool          thumb{false};
};

}  // namespace abcpwn::commands
