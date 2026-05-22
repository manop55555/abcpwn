// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::formats::elf {

// ELF-specific convenience: return the BinaryInfo only if the loaded
// binary is actually an ELF; otherwise nullptr.
[[nodiscard]] inline const BinaryInfo* try_get(const LoadedBinary& b) noexcept {
    return (b.info().format == BinaryFormat::Elf) ? &b.info() : nullptr;
}

}  // namespace abcpwn::formats::elf
