// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "abcpwn/core/result.hpp"

namespace abcpwn::commands::encoding {

enum class Endian : std::uint8_t { Little = 0, Big = 1 };

// Pack an unsigned integer to `width` bytes in `endian` order. Width
// must be 1, 2, 4, or 8.
[[nodiscard]] core::Result<std::vector<std::uint8_t>>
pack(std::uint64_t value, unsigned width, Endian endian);

[[nodiscard]] core::Result<std::uint64_t> unpack(std::span<const std::uint8_t> bytes,
                                                 Endian endian);

// Hex encode (lowercase). `delim` is inserted between bytes; pass ""
// for compact.
[[nodiscard]] std::string hex_encode(std::span<const std::uint8_t> bytes,
                                     std::string_view delim = "");

[[nodiscard]] core::Result<std::vector<std::uint8_t>> hex_decode(std::string_view text);

[[nodiscard]] std::string base64_encode(std::span<const std::uint8_t> bytes);

[[nodiscard]] core::Result<std::vector<std::uint8_t>> base64_decode(std::string_view text);

[[nodiscard]] std::vector<std::uint8_t> xor_with_key(std::span<const std::uint8_t> bytes,
                                                     std::span<const std::uint8_t> key) noexcept;

// errno table: POSIX errno number -> name and short message. Linux
// glibc layout (the only OS abcpwn targets natively).
struct ErrnoEntry {
    int number;
    std::string_view name;
    std::string_view message;
};

[[nodiscard]] const ErrnoEntry* errno_by_number(int number) noexcept;
[[nodiscard]] const ErrnoEntry* errno_by_name(std::string_view name) noexcept;
[[nodiscard]] std::span<const ErrnoEntry> errno_table() noexcept;

// constgrep table: compiled-in known constants frequently seen in
// pwn challenges (mmap protection flags, common signal numbers,
// ELF auxv types, etc.). Search is substring on name.
struct Constant {
    std::string_view category;
    std::string_view name;
    std::int64_t value;
};

[[nodiscard]] std::vector<Constant> constgrep_search(std::string_view query,
                                                     std::string_view category = "") noexcept;

[[nodiscard]] std::span<const Constant> constgrep_table() noexcept;

} // namespace abcpwn::commands::encoding
