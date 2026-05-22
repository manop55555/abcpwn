// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// libFuzzer harness for the cBPF seccomp decoder + disassembler. The
// decoder returns InvalidInput on a non-multiple-of-8 buffer, so we
// pad / truncate to keep iterations productive.

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/seccomp.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Round size down to a multiple of 8 so the decoder advances; the
    // padding case is exercised separately by the unit tests.
    const std::size_t aligned = size - (size % 8U);
    if (aligned == 0) {
        return 0;
    }
    const std::span<const std::uint8_t> view(data, aligned);
    auto decoded = abcpwn::commands::seccomp::decode_bpf(view);
    if (!decoded) {
        return 0;
    }
    (void) abcpwn::commands::seccomp::disassemble_bpf(
        *decoded, abcpwn::arch::Arch::X86_64);
    return 0;
}
