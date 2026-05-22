// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::libc {

// Compile-time toggle for the network-gated `libc download` path.
[[nodiscard]] constexpr bool network_compiled_in() noexcept {
#if defined(ABCPWN_WITH_NETWORK) && ABCPWN_WITH_NETWORK
    return true;
#else
    return false;
#endif
}

class LibcCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "libc";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "identify and inspect glibc versions";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string action{};                    // id | offsets | diff | download | search
    std::vector<std::string> offset_pairs{}; // for `id`: sym:hex (repeatable)
    std::string symbol{};                    // for `offsets`: filter
    std::string identifier{};                // for `offsets` / `download` / `search` argument
    std::string other{};                     // for `diff` second id
};

} // namespace abcpwn::commands::libc
