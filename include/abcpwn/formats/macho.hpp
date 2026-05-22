// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::formats::macho {

[[nodiscard]] inline const BinaryInfo* try_get(const LoadedBinary& b) noexcept {
    return (b.info().format == BinaryFormat::MachO) ? &b.info() : nullptr;
}

}  // namespace abcpwn::formats::macho
