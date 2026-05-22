// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands {

struct ExtractedString {
    std::uint64_t offset{0};
    std::string value{};
};

// Scan `data` for printable ASCII strings of at least `min_length`
// bytes. Returns at most `max_results` hits.
[[nodiscard]] std::vector<ExtractedString> extract_ascii_strings(std::span<const std::uint8_t> data,
                                                                 std::size_t min_length,
                                                                 std::size_t max_results);

class StringsCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "strings";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "list printable strings in a binary";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string target{};
    std::size_t min_length{4};
    std::size_t max_results{10000};
};

} // namespace abcpwn::commands
