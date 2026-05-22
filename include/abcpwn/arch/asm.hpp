// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/core/result.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace abcpwn::arch {

struct AsmOptions {
    Arch          arch{Arch::X86_64};
    Endian        endian{Endian::Little};
    bool          thumb_mode{false};
    std::uint64_t base_address{0};
};

// Compile assembly text into raw bytes. Implementation is gated by the
// `ABCPWN_WITH_KEYSTONE` build flag (Keystone is GPL-2 only). The
// header is always compiled; calling assemble() in an Apache-2.0 build
// returns FeatureDisabled with a message pointing at the abcpwn-full
// release artifact.
[[nodiscard]] core::Result<std::vector<std::uint8_t>> assemble(
    std::string_view    source,
    const AsmOptions&   opts);

[[nodiscard]] constexpr bool keystone_compiled_in() noexcept {
#if defined(ABCPWN_WITH_KEYSTONE) && ABCPWN_WITH_KEYSTONE
    return true;
#else
    return false;
#endif
}

}  // namespace abcpwn::arch
