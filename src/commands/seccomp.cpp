// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/seccomp.hpp"

#include "abcpwn/arch/syscalls.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/safe_io.hpp"

#include <CLI/CLI.hpp>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands::seccomp {

namespace {

// cBPF instruction classes (low 3 bits of `code`).
constexpr std::uint16_t kBpfLd  = 0x00;
constexpr std::uint16_t kBpfLdx = 0x01;
constexpr std::uint16_t kBpfSt  = 0x02;
constexpr std::uint16_t kBpfStx = 0x03;
constexpr std::uint16_t kBpfAlu = 0x04;
constexpr std::uint16_t kBpfJmp = 0x05;
constexpr std::uint16_t kBpfRet = 0x06;
constexpr std::uint16_t kBpfMisc = 0x07;

// Size modifiers (bits 3-4).
constexpr std::uint16_t kBpfW  = 0x00;
constexpr std::uint16_t kBpfH  = 0x08;
constexpr std::uint16_t kBpfB  = 0x10;

// Addressing modes (bits 5-7).
constexpr std::uint16_t kBpfAbs = 0x20;
constexpr std::uint16_t kBpfInd = 0x40;
constexpr std::uint16_t kBpfImm = 0x00;
constexpr std::uint16_t kBpfMem = 0x60;
constexpr std::uint16_t kBpfLen = 0x80;

// ALU ops (bits 4-7 of `code`).
constexpr std::uint16_t kBpfAdd = 0x00;
constexpr std::uint16_t kBpfSub = 0x10;
constexpr std::uint16_t kBpfMul = 0x20;
constexpr std::uint16_t kBpfDiv = 0x30;
constexpr std::uint16_t kBpfOr  = 0x40;
constexpr std::uint16_t kBpfAnd = 0x50;
constexpr std::uint16_t kBpfLsh = 0x60;
constexpr std::uint16_t kBpfRsh = 0x70;
constexpr std::uint16_t kBpfNeg = 0x80;
constexpr std::uint16_t kBpfXor = 0xa0;

// Conditional jumps (bits 4-7 of `code` when class == JMP).
constexpr std::uint16_t kBpfJa  = 0x00;
constexpr std::uint16_t kBpfJeq = 0x10;
constexpr std::uint16_t kBpfJgt = 0x20;
constexpr std::uint16_t kBpfJge = 0x30;
constexpr std::uint16_t kBpfJset = 0x40;

// SECCOMP_RET_* action codes.
constexpr std::uint32_t kSeccompRetKill    = 0x00000000;
constexpr std::uint32_t kSeccompRetTrap    = 0x00030000;
constexpr std::uint32_t kSeccompRetErrno   = 0x00050000;
constexpr std::uint32_t kSeccompRetTrace   = 0x7ff00000;
constexpr std::uint32_t kSeccompRetAllow   = 0x7fff0000;
constexpr std::uint32_t kSeccompRetLog     = 0x7ffc0000;

[[nodiscard]] std::string action_name(std::uint32_t k) {
    const std::uint32_t a = k & 0xffff0000U;
    switch (a) {
        case kSeccompRetKill:    return "KILL";
        case kSeccompRetTrap:    return "TRAP";
        case kSeccompRetErrno:   return "ERRNO(" + std::to_string(k & 0xffffU) + ")";
        case kSeccompRetTrace:   return "TRACE";
        case kSeccompRetAllow:   return "ALLOW";
        case kSeccompRetLog:     return "LOG";
        default: {
            char buf[24];
            std::snprintf(buf, sizeof buf, "0x%08x", k);
            return std::string(buf);
        }
    }
}

[[nodiscard]] std::string alu_mnemonic(std::uint16_t op) {
    switch (op) {
        case kBpfAdd: return "+=";
        case kBpfSub: return "-=";
        case kBpfMul: return "*=";
        case kBpfDiv: return "/=";
        case kBpfOr:  return "|=";
        case kBpfAnd: return "&=";
        case kBpfLsh: return "<<=";
        case kBpfRsh: return ">>=";
        case kBpfXor: return "^=";
        default:      return "??";
    }
}

}  // namespace

core::Result<std::vector<BpfInsn>> decode_bpf(std::span<const std::uint8_t> bytes) {
    if (bytes.size() % 8 != 0) {
        return core::err(core::ErrorCode::InvalidInput,
            "seccomp: BPF buffer must be a multiple of 8 bytes");
    }
    std::vector<BpfInsn> out;
    out.reserve(bytes.size() / 8);
    for (std::size_t i = 0; i < bytes.size(); i += 8) {
        BpfInsn ins;
        ins.code = static_cast<std::uint16_t>(bytes[i] | (bytes[i + 1] << 8));
        ins.jt   = bytes[i + 2];
        ins.jf   = bytes[i + 3];
        ins.k    = static_cast<std::uint32_t>(bytes[i + 4])
                 | (static_cast<std::uint32_t>(bytes[i + 5]) << 8)
                 | (static_cast<std::uint32_t>(bytes[i + 6]) << 16)
                 | (static_cast<std::uint32_t>(bytes[i + 7]) << 24);
        out.push_back(ins);
    }
    return out;
}

std::vector<std::string> disassemble_bpf(
    std::span<const BpfInsn> insns,
    arch::Arch               arch_for_syscalls)
{
    std::vector<std::string> out;
    out.reserve(insns.size());
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        char prefix[8];
        std::snprintf(prefix, sizeof prefix, "%3zu: ", i);
        std::string line(prefix);

        const std::uint16_t cls = ins.code & 0x07;
        if (cls == kBpfLd && (ins.code & 0x60) == kBpfAbs) {
            // A = data[k]  -- in seccomp_data the layout is:
            //   0: nr (syscall number)
            //   4: arch
            //   8: instruction pointer
            //   ... (16: args[0..5])
            char buf[64];
            const char* what = "data";
            if (ins.k == 0)       what = "sys_number";
            else if (ins.k == 4)  what = "arch";
            else if (ins.k == 8)  what = "ip_lo";
            else if (ins.k == 12) what = "ip_hi";
            std::snprintf(buf, sizeof buf, "A = %s", what);
            line.append(buf);
        } else if (cls == kBpfRet) {
            line.append("return ");
            line.append(action_name(ins.k));
        } else if (cls == kBpfJmp) {
            const std::uint16_t op = ins.code & 0xf0;
            char buf[96];
            if (op == kBpfJa) {
                std::snprintf(buf, sizeof buf, "goto %zu", i + 1 + ins.k);
            } else {
                const char* cmp = "??";
                if      (op == kBpfJeq) cmp = "==";
                else if (op == kBpfJgt) cmp = ">";
                else if (op == kBpfJge) cmp = ">=";
                else if (op == kBpfJset) cmp = "&";
                std::snprintf(buf, sizeof buf,
                    "if (A %s 0x%x) goto %zu else goto %zu",
                    cmp, ins.k, i + 1 + ins.jt, i + 1 + ins.jf);
            }
            line.append(buf);
            // Annotate with syscall name when comparing A == k against
            // a known number on the current arch.
            if ((ins.code & 0xf0) == kBpfJeq) {
                if (auto n = arch::syscalls::by_number(
                    arch_for_syscalls, static_cast<std::int32_t>(ins.k)))
                {
                    line.append("  // SYS_");
                    line.append(*n);
                }
            }
        } else if (cls == kBpfAlu) {
            const std::uint16_t op = ins.code & 0xf0;
            char buf[64];
            std::snprintf(buf, sizeof buf, "A %s 0x%x", alu_mnemonic(op).c_str(), ins.k);
            line.append(buf);
        } else {
            char buf[64];
            std::snprintf(buf, sizeof buf, "<unhandled code=0x%04x k=0x%08x>",
                ins.code, ins.k);
            line.append(buf);
        }
        out.push_back(std::move(line));
    }
    return out;
}

void SeccompCommand::setup(CLI::App& app) {
    app.add_option("action", action,
        "disasm | dump | asm | emu")->required();
    app.add_option("input", input,
        "Hex BPF bytes for disasm/emu; BPF source for asm; path for dump");
    app.add_option("--arch", arch_str,
        "Arch for syscall-name annotations (x86_64 default)");
}

core::Result<core::CommandResult> SeccompCommand::run(const core::Context& /*ctx*/) {
    const auto a = arch::arch_from_string(arch_str);
    if (!a) {
        return core::err(core::ErrorCode::UsageError,
            "seccomp: unknown --arch '" + arch_str + "'");
    }

    if (action == "disasm") {
        auto bytes = encoding::hex_decode(input);
        if (!bytes) {
            return core::err(bytes.error());
        }
        auto decoded = decode_bpf(*bytes);
        if (!decoded) {
            return core::err(decoded.error());
        }
        const auto lines = disassemble_bpf(*decoded, *a);
        core::CommandResult res;
        res.raw_lines = std::move(const_cast<std::vector<std::string>&>(lines));
        res.summary = std::to_string(decoded->size()) + " BPF instructions";
        return res;
    }
    if (action == "dump") {
        // dump <binary>: find seccomp_load() in the target. The full
        // implementation walks .rodata for a struct sock_fprog
        // referenced by a seccomp_load call site -- target-specific
        // and significantly more analysis. v0.1 defers and tells the
        // user to pipe the filter bytes through `seccomp disasm`.
        return core::err(core::ErrorCode::Unsupported,
            "seccomp: 'dump' is deferred to a later milestone. "
            "Extract the filter bytes manually (gdb / ldd / strace) "
            "and run `abcpwn seccomp disasm <hex>`.");
    }
    if (action == "asm" || action == "emu") {
        return core::err(core::ErrorCode::Unsupported,
            "seccomp: '" + action + "' is deferred to a later milestone. "
            "The BPF disassembler is in place and the emulator path "
            "follows once Unicorn (ABCPWN_WITH_UNICORN) lands.");
    }
    return core::err(core::ErrorCode::UsageError,
        "seccomp: unknown action '" + action + "'");
}

}  // namespace abcpwn::commands::seccomp
