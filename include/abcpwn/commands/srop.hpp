// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace abcpwn::commands::srop {

// x86_64 sigreturn frame layout (subset of `struct ucontext_t` + the
// `rt_sigreturn` syscall trampoline). Aligned to match the kernel's
// expectation; only the fields callers commonly need are exposed in
// the struct -- the rest are zeroed in the emitted bytes.
struct FrameX86_64 {
    std::uint64_t rax{0};
    std::uint64_t rbx{0};
    std::uint64_t rcx{0};
    std::uint64_t rdx{0};
    std::uint64_t rsi{0};
    std::uint64_t rdi{0};
    std::uint64_t rbp{0};
    std::uint64_t rsp{0};
    std::uint64_t r8{0};
    std::uint64_t r9{0};
    std::uint64_t r10{0};
    std::uint64_t r11{0};
    std::uint64_t r12{0};
    std::uint64_t r13{0};
    std::uint64_t r14{0};
    std::uint64_t r15{0};
    std::uint64_t rip{0};
    std::uint64_t cs{0x33};
    std::uint64_t ss{0x2b};
    std::uint64_t fs_base{0};
    std::uint64_t gs_base{0};
};

// Serialize an x86_64 sigreturn frame to raw bytes (little-endian,
// padded with zeros where the kernel frame has more state).
[[nodiscard]] std::vector<std::uint8_t> serialize_frame(const FrameX86_64& f);

class SropCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "srop"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "build a sigreturn-oriented programming frame";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string arch_str{"x86_64"};
    std::int64_t syscall_number{-1};
    std::vector<std::uint64_t> syscall_args{};
    std::uint64_t rip{0};
    std::uint64_t rsp{0};
};

}  // namespace abcpwn::commands::srop
