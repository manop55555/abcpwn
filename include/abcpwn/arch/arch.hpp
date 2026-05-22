// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace abcpwn::arch {

enum class Arch : std::uint8_t {
    Unknown = 0,
    X86 = 1,
    X86_64 = 2,
    Arm = 3,
    Aarch64 = 4,
    Mips = 5,
    Mips64 = 6,
    Ppc = 7,
    Ppc64 = 8,
    Riscv32 = 9,
    Riscv64 = 10,
};

enum class Endian : std::uint8_t {
    Little = 0,
    Big = 1,
};

[[nodiscard]] std::string_view arch_name(Arch a) noexcept;

// Best-effort string-to-Arch parse. Accepts names produced by the
// binary loader as well as common aliases used by CTF players
// ("amd64" -> X86_64, "arm32" -> Arm, ...).
[[nodiscard]] std::optional<Arch> arch_from_string(std::string_view s) noexcept;

// Bit width of pointers on the given arch (16/32/64).
[[nodiscard]] unsigned arch_bits(Arch a) noexcept;

// Native byte order of the arch when not configured to swap (most
// arches default to little-endian; PPC defaults to big).
[[nodiscard]] Endian default_endian(Arch a) noexcept;

} // namespace abcpwn::arch
