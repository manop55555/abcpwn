// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands::seccomp {

// Linux cBPF instruction layout (16-bit code + 8/8 jt/jf + 32-bit k),
// 8 bytes wide. Each seccomp filter is a sequence of these.
struct BpfInsn {
    std::uint16_t code{0};
    std::uint8_t  jt{0};
    std::uint8_t  jf{0};
    std::uint32_t k{0};
};

// Parse a contiguous buffer of cBPF instructions. Returns an error
// when the buffer length is not a multiple of 8 bytes.
[[nodiscard]] core::Result<std::vector<BpfInsn>> decode_bpf(
    std::span<const std::uint8_t> bytes);

// Render a parsed filter as the canonical seccomp dump (one line per
// instruction, mnemonic + comment annotating well-known syscall
// numbers for the chosen arch).
[[nodiscard]] std::vector<std::string> disassemble_bpf(
    std::span<const BpfInsn> insns,
    arch::Arch               arch_for_syscalls = arch::Arch::X86_64);

class SeccompCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "seccomp"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "decode and reason about seccomp BPF filters";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string action{};
    std::string input{};
    std::string arch_str{"x86_64"};
};

}  // namespace abcpwn::commands::seccomp
