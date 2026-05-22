// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::safe_link {

// glibc safe-linking encoding (added in 2.32, applied to every freed
// chunk's fd before storage). The encoded value depends both on the
// pointer being stored AND on the address where it will be stored:
//
//     encoded = ptr ^ (pos >> 12)
//
// Decoding is the same operation -- XOR is self-inverse -- as long as
// the storage position is unchanged, which it is when reading back.
[[nodiscard]] constexpr std::uint64_t safe_link_encode(std::uint64_t ptr,
                                                       std::uint64_t pos) noexcept {
    return ptr ^ (pos >> 12);
}

[[nodiscard]] constexpr std::uint64_t safe_link_decode(std::uint64_t encoded,
                                                       std::uint64_t pos) noexcept {
    return encoded ^ (pos >> 12);
}

class SafeLinkCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "safe-link";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "encode or decode glibc safe-linking obfuscation";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::uint64_t ptr_or_encoded{0};
    std::uint64_t pos{0};
    bool encode{true}; // default: encode; --decode flips
};

} // namespace abcpwn::commands::safe_link
