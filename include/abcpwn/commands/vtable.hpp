// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::vtable {

class VtableCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "vtable";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "list / analyze / hijack C++ vtables in an ELF";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    bool list{false};
    std::uint64_t analyze_addr{0};
    std::uint64_t hijack_vtable{0};
    std::int64_t hijack_method_idx{-1};
    std::uint64_t hijack_target{0};
};

} // namespace abcpwn::commands::vtable
