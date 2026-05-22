// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::commands {

// Pwntools-compatible de Bruijn-style cyclic generator.
[[nodiscard]] std::string cyclic_generate(std::size_t length,
                                          std::string_view alphabet = "abcdefghijklmnopqrstuvwxyz",
                                          std::size_t subseq_length = 4);

// Locate `needle` (interpreted as a subseq of `subseq_length` bytes)
// within the conceptual cyclic sequence, returning the offset in the
// generated buffer. Returns nullopt if not present.
[[nodiscard]] std::optional<std::size_t>
cyclic_find(std::string_view needle,
            std::string_view alphabet = "abcdefghijklmnopqrstuvwxyz",
            std::size_t subseq_length = 4);

class CyclicCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "cyclic";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "generate or search a pwntools-style cyclic sequence";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::size_t length{0};
    std::size_t subseq_length{4};
    std::string alphabet{"abcdefghijklmnopqrstuvwxyz"};
    std::string find{};
};

} // namespace abcpwn::commands
