// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands {

struct SearchHit {
    std::uint64_t offset{0};
    std::size_t   length{0};
};

// Locate every occurrence of `needle` in `data`. Linear scan; suitable
// for small-to-medium binaries.
[[nodiscard]] std::vector<SearchHit> search_bytes(
    std::span<const std::uint8_t> data,
    std::span<const std::uint8_t> needle);

class SearchCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "search"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "search a binary for ASCII or hex byte patterns";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::string pattern{};
    bool        as_hex{false};
    bool        count_only{false};
};

}  // namespace abcpwn::commands
