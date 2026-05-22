// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::pwninit {

[[nodiscard]] constexpr bool network_compiled_in() noexcept {
#if defined(ABCPWN_WITH_NETWORK) && ABCPWN_WITH_NETWORK
    return true;
#else
    return false;
#endif
}

class PwninitCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "pwninit";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "set up a CTF pwn challenge workspace";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string directory{"."};
    std::string bin_path{};
    std::string libc_path{};
    std::string ld_path{};
    std::string template_strategy{"ret2libc"};
    bool no_patch{false};
};

} // namespace abcpwn::commands::pwninit
