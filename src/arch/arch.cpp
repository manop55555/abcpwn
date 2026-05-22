// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/arch/arch.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <string>
#include <string_view>

namespace abcpwn::arch {

std::string_view arch_name(Arch a) noexcept {
    switch (a) {
    case Arch::Unknown:
        return "unknown";
    case Arch::X86:
        return "i386";
    case Arch::X86_64:
        return "x86_64";
    case Arch::Arm:
        return "arm";
    case Arch::Aarch64:
        return "aarch64";
    case Arch::Mips:
        return "mips";
    case Arch::Mips64:
        return "mips64";
    case Arch::Ppc:
        return "ppc";
    case Arch::Ppc64:
        return "ppc64";
    case Arch::Riscv32:
        return "riscv32";
    case Arch::Riscv64:
        return "riscv64";
    }
    return "unknown";
}

std::optional<Arch> arch_from_string(std::string_view s) noexcept {
    std::string lower;
    lower.reserve(s.size());
    for (char c : s) {
        lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    static constexpr std::array<std::pair<std::string_view, Arch>, 22> table = {{
        {"x86_64", Arch::X86_64},   {"amd64", Arch::X86_64},    {"x64", Arch::X86_64},
        {"i386", Arch::X86},        {"i686", Arch::X86},        {"x86", Arch::X86},
        {"arm", Arch::Arm},         {"arm32", Arch::Arm},       {"armv7", Arch::Arm},
        {"aarch64", Arch::Aarch64}, {"arm64", Arch::Aarch64},   {"armv8", Arch::Aarch64},
        {"mips", Arch::Mips},       {"mips32", Arch::Mips},     {"mips64", Arch::Mips64},
        {"ppc", Arch::Ppc},         {"powerpc", Arch::Ppc},     {"ppc64", Arch::Ppc64},
        {"riscv", Arch::Riscv64},   {"riscv32", Arch::Riscv32}, {"riscv64", Arch::Riscv64},
        {"rv64", Arch::Riscv64},
    }};
    for (const auto& [name, val] : table) {
        if (lower == name)
            return val;
    }
    return std::nullopt;
}

unsigned arch_bits(Arch a) noexcept {
    switch (a) {
    case Arch::X86:
    case Arch::Arm:
    case Arch::Mips:
    case Arch::Ppc:
    case Arch::Riscv32:
        return 32;
    case Arch::X86_64:
    case Arch::Aarch64:
    case Arch::Mips64:
    case Arch::Ppc64:
    case Arch::Riscv64:
        return 64;
    case Arch::Unknown:
        return 0;
    }
    return 0;
}

Endian default_endian(Arch a) noexcept {
    switch (a) {
    case Arch::Ppc:
    case Arch::Ppc64:
        return Endian::Big;
    default:
        return Endian::Little;
    }
}

} // namespace abcpwn::arch
