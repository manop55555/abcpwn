// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/core/result.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::arch {

struct DisasmOptions {
    Arch         arch{Arch::X86_64};
    Endian       endian{Endian::Little};
    bool         thumb_mode{false};  // ARM Thumb encoding
    std::uint64_t base_address{0};
    std::size_t  max_instructions{0};  // 0 = unlimited
};

struct Instruction {
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes{};
    std::string  mnemonic{};
    std::string  op_str{};

    [[nodiscard]] std::string text() const {
        return mnemonic + (op_str.empty() ? "" : " " + op_str);
    }
};

// Disassemble a byte buffer. Returns an empty vector when no
// instructions could be decoded; returns an error only for setup
// failures (unsupported arch, Capstone init failure).
[[nodiscard]] core::Result<std::vector<Instruction>> disassemble(
    std::span<const std::uint8_t> bytes,
    const DisasmOptions&          opts);

}  // namespace abcpwn::arch
