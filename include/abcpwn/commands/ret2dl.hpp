// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::ret2dl {

class Ret2dlCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "ret2dl";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "ret2dlresolve helper: locate dynamic linker structures";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::string symbol{};
    std::uint64_t base{0};
    std::string bad_chars_hex{};
};

} // namespace abcpwn::commands::ret2dl
