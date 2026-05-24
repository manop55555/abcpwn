// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <string>

#include "abcpwn/commands/rop_search.hpp"
#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

class GadgetCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "gadget";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "find ROP gadgets in a binary's executable sections";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::size_t depth{10};
    std::string terminator{"ret"};
    std::string filter{};
    std::string bad_chars_hex{};
    std::string format{"pretty"};
    std::size_t max_results{1'000'000};
    bool no_progress{false};
};

} // namespace abcpwn::commands
