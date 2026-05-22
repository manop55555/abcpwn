// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/arch/syscalls.hpp"

#include <array>
#include <span>
#include <string_view>

namespace abcpwn::arch::syscalls {

// We carry the shortlist of CTF-relevant syscalls per arch. This is
// not a complete table; the assumption is users who need esoteric
// numbers consult the kernel headers directly.

namespace {

constexpr std::array<Entry, 38> kX86_64 = {{
    {0,   "read"},      {1,   "write"},     {2,   "open"},
    {3,   "close"},     {5,   "fstat"},     {9,   "mmap"},
    {10,  "mprotect"},  {11,  "munmap"},    {12,  "brk"},
    {21,  "access"},    {32,  "dup"},       {33,  "dup2"},
    {39,  "getpid"},    {41,  "socket"},    {42,  "connect"},
    {43,  "accept"},    {49,  "bind"},      {50,  "listen"},
    {57,  "fork"},      {58,  "vfork"},     {59,  "execve"},
    {60,  "exit"},      {62,  "kill"},      {72,  "fcntl"},
    {80,  "chdir"},     {82,  "rename"},    {83,  "mkdir"},
    {84,  "rmdir"},     {85,  "creat"},     {87,  "unlink"},
    {88,  "symlink"},   {89,  "readlink"},  {101, "ptrace"},
    {105, "setuid"},    {158, "arch_prctl"},
    {231, "exit_group"},{257, "openat"},    {322, "execveat"},
}};

constexpr std::array<Entry, 27> kX86 = {{
    {1,   "exit"},      {2,   "fork"},      {3,   "read"},
    {4,   "write"},     {5,   "open"},      {6,   "close"},
    {7,   "waitpid"},   {8,   "creat"},     {9,   "link"},
    {10,  "unlink"},    {11,  "execve"},    {12,  "chdir"},
    {19,  "lseek"},     {20,  "getpid"},    {37,  "kill"},
    {41,  "dup"},       {45,  "brk"},       {54,  "ioctl"},
    {63,  "dup2"},      {90,  "mmap"},      {91,  "munmap"},
    {102, "socketcall"},{125, "mprotect"},  {158, "sched_yield"},
    {252, "exit_group"},{295, "openat"},    {358, "execveat"},
}};

constexpr std::array<Entry, 27> kArm = {{
    {1,   "exit"},      {2,   "fork"},      {3,   "read"},
    {4,   "write"},     {5,   "open"},      {6,   "close"},
    {11,  "execve"},    {19,  "lseek"},     {20,  "getpid"},
    {37,  "kill"},      {41,  "dup"},       {45,  "brk"},
    {54,  "ioctl"},     {63,  "dup2"},      {120, "clone"},
    {125, "mprotect"},  {158, "sched_yield"},
    {192, "mmap2"},     {220, "getdents64"},{248, "exit_group"},
    {281, "socket"},    {283, "connect"},   {285, "accept"},
    {287, "bind"},      {322, "openat"},    {387, "execveat"},
    {983045, "ARM_set_tls"},
}};

constexpr std::array<Entry, 23> kAarch64 = {{
    {21,  "access"},    {35,  "unlinkat"},  {56,  "openat"},
    {57,  "close"},     {63,  "read"},      {64,  "write"},
    {93,  "exit"},      {94,  "exit_group"},
    {129, "kill"},      {172, "getpid"},    {214, "brk"},
    {215, "munmap"},    {220, "clone"},     {221, "execve"},
    {222, "mmap"},      {226, "mprotect"},
    {198, "socket"},    {200, "bind"},      {201, "listen"},
    {202, "accept"},    {203, "connect"},
    {221, "execve"},    {281, "execveat"},
}};

constexpr std::array<Entry, 18> kMips = {{
    {4001, "exit"},     {4002, "fork"},     {4003, "read"},
    {4004, "write"},    {4005, "open"},     {4006, "close"},
    {4011, "execve"},   {4020, "getpid"},   {4037, "kill"},
    {4041, "dup"},      {4045, "brk"},      {4054, "ioctl"},
    {4063, "dup2"},     {4125, "mprotect"}, {4192, "mmap2"},
    {4246, "exit_group"},
    {4288, "openat"},   {4361, "execveat"},
}};

constexpr std::array<Entry, 18> kRiscv64 = {{
    {21,  "access"},    {35,  "unlinkat"},  {56,  "openat"},
    {57,  "close"},     {63,  "read"},      {64,  "write"},
    {93,  "exit"},      {94,  "exit_group"},
    {129, "kill"},      {172, "getpid"},    {214, "brk"},
    {215, "munmap"},    {220, "clone"},     {221, "execve"},
    {222, "mmap"},      {226, "mprotect"},
    {198, "socket"},    {281, "execveat"},
}};

constexpr std::span<const Entry> empty_table() noexcept {
    return {};
}

}  // namespace

std::span<const Entry> table_for(Arch a) noexcept {
    switch (a) {
        case Arch::X86_64:  return kX86_64;
        case Arch::X86:     return kX86;
        case Arch::Arm:     return kArm;
        case Arch::Aarch64: return kAarch64;
        case Arch::Mips:    return kMips;
        case Arch::Riscv64: return kRiscv64;
        default:            return empty_table();
    }
}

std::optional<std::int32_t> by_name(Arch a, std::string_view name) noexcept {
    for (const auto& e : table_for(a)) {
        if (e.name == name) return e.number;
    }
    return std::nullopt;
}

std::optional<std::string_view> by_number(Arch a, std::int32_t number) noexcept {
    for (const auto& e : table_for(a)) {
        if (e.number == number) return e.name;
    }
    return std::nullopt;
}

}  // namespace abcpwn::arch::syscalls
