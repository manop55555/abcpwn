// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands::diffpatch {

struct ByteDelta {
    std::uint64_t offset{0};
    std::uint8_t  a{0};
    std::uint8_t  b{0};
};

[[nodiscard]] std::vector<ByteDelta> byte_diff(
    std::span<const std::uint8_t> a,
    std::span<const std::uint8_t> b);

class DiffCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "diff"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "byte-level diff between two binaries";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string file_a{};
    std::string file_b{};
    bool        bytes_only{true};  // default: byte-level diff
    std::size_t max_results{1024};
};

}  // namespace abcpwn::commands::diffpatch
