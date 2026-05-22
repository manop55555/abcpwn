// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/srop.hpp"

#include "abcpwn/commands/encoding.hpp"

#include <CLI/CLI.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands::srop {

namespace {

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) {
        out.push_back(static_cast<std::uint8_t>((v >> (i * 8)) & 0xffU));
    }
}

}  // namespace

std::vector<std::uint8_t> serialize_frame(const FrameX86_64& f) {
    // Layout follows the Linux x86_64 `struct sigframe` ucontext
    // layout (kernel/sys.c rt_sigreturn handler). The frame begins
    // with the uc_flags (8) + uc_link (8) padding, then uc_stack
    // (24 bytes), then the GP register block. We emit exactly the
    // 248-byte minimum and zero everything not explicitly set. This
    // is sufficient for sigreturn to restore registers and continue.
    std::vector<std::uint8_t> out;
    out.reserve(248);

    // uc_flags, uc_link, uc_stack (32 bytes of zeros)
    for (int i = 0; i < 32; ++i) out.push_back(0);
    // uc_stack.ss_size + alignment padding
    for (int i = 0; i < 8; ++i) out.push_back(0);

    // gp register block (regs in kernel-defined order)
    put_u64(out, f.r8);
    put_u64(out, f.r9);
    put_u64(out, f.r10);
    put_u64(out, f.r11);
    put_u64(out, f.r12);
    put_u64(out, f.r13);
    put_u64(out, f.r14);
    put_u64(out, f.r15);
    put_u64(out, f.rdi);
    put_u64(out, f.rsi);
    put_u64(out, f.rbp);
    put_u64(out, f.rbx);
    put_u64(out, f.rdx);
    put_u64(out, f.rax);
    put_u64(out, f.rcx);
    put_u64(out, f.rsp);
    put_u64(out, f.rip);

    // eflags, cs/gs/fs/ss
    put_u64(out, 0x202);              // eflags with reserved bit set
    put_u64(out, (f.cs | (f.ss << 16)));
    put_u64(out, 0);                  // err
    put_u64(out, 0);                  // trapno
    put_u64(out, 0);                  // oldmask
    put_u64(out, 0);                  // cr2
    put_u64(out, 0);                  // &fpstate (NULL: kernel skips FP restore)
    put_u64(out, 0);                  // __reserved
    put_u64(out, 0);                  // sigmask
    return out;
}

void SropCommand::setup(CLI::App& app) {
    app.add_option("--arch", arch_str, "x86_64 (default)");
    app.add_option("--syscall", syscall_number,
        "Build a syscall sigframe with this syscall number in rax");
    app.add_option("--syscall-arg", syscall_args,
        "Append per arg: --syscall-arg <value>");
    app.add_option("--rip", rip, "Set RIP (hex)");
    app.add_option("--rsp", rsp, "Set RSP (hex)");
}

core::Result<core::CommandResult> SropCommand::run(const core::Context& /*ctx*/) {
    if (arch_str != "x86_64") {
        return core::err(core::ErrorCode::Unsupported,
            "srop: only x86_64 sigreturn frames are implemented in this milestone");
    }
    FrameX86_64 f;
    if (syscall_number >= 0) {
        f.rax = static_cast<std::uint64_t>(syscall_number);
        if (!syscall_args.empty())     f.rdi = syscall_args[0];
        if (syscall_args.size() >= 2)  f.rsi = syscall_args[1];
        if (syscall_args.size() >= 3)  f.rdx = syscall_args[2];
        if (syscall_args.size() >= 4)  f.r10 = syscall_args[3];
        if (syscall_args.size() >= 5)  f.r8  = syscall_args[4];
        if (syscall_args.size() >= 6)  f.r9  = syscall_args[5];
    }
    f.rip = rip;
    f.rsp = rsp;
    const auto bytes = serialize_frame(f);
    core::CommandResult res;
    res.raw_lines.push_back(encoding::hex_encode(bytes));
    res.summary = "sigframe " + std::to_string(bytes.size()) + " bytes";
    return res;
}

}  // namespace abcpwn::commands::srop
