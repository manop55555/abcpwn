// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/arch/arch.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace abcpwn::arch::syscalls {

struct Entry {
    std::int32_t      number;
    std::string_view  name;
};

// Look up a syscall number by name on the given arch. Returns
// nullopt when the syscall is not in our table (the project covers
// the common CTF/pwn shortlist, not every Linux syscall).
[[nodiscard]] std::optional<std::int32_t> by_name(Arch a, std::string_view name) noexcept;

// Look up a syscall name by number on the given arch.
[[nodiscard]] std::optional<std::string_view> by_number(Arch a, std::int32_t number) noexcept;

// Full table for an arch (read-only span into static storage).
[[nodiscard]] std::span<const Entry> table_for(Arch a) noexcept;

}  // namespace abcpwn::arch::syscalls
