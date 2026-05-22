// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// libFuzzer harness for the format-string analysis surface. Both the
// printf-dump tokenizer (find_marker_offset) and the leak-payload
// builder are exercised; the write-payload builder is also driven
// when the input shape allows.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/fmt.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > (64U * 1024U)) {
        return 0;
    }
    const std::string_view input(reinterpret_cast<const char*>(data), size);
    (void) abcpwn::commands::fmt::find_marker_offset(input);

    // Use the first byte (when present) to drive build_leak_payload
    // through a range of indices; cheap enough per iteration.
    if (size > 0) {
        (void) abcpwn::commands::fmt::build_leak_payload(static_cast<std::size_t>(data[0]));
    }

    // When the input is long enough, treat the first 24 bytes as
    // (target_addr, value, arg_index) and try the write payload too.
    if (size >= 24) {
        abcpwn::commands::fmt::WriteSpec ws;
        // Reinterpret the prefix as three 64-bit fields. UB-wise this
        // is fine because the fuzzer feeds arbitrary bytes by design.
        std::uint64_t target = 0, value = 0;
        std::size_t idx = 0;
        for (int i = 0; i < 8; ++i) {
            target |= static_cast<std::uint64_t>(data[i]) << (i * 8);
            value |= static_cast<std::uint64_t>(data[i + 8]) << (i * 8);
        }
        for (int i = 0; i < 8; ++i) {
            idx |= static_cast<std::size_t>(data[i + 16]) << (i * 8);
        }
        ws.target_address = target;
        ws.value = value;
        ws.arg_index = (idx % 1024U) + 1U; // keep arg idx bounded
        ws.arch = abcpwn::arch::Arch::X86_64;
        ws.padding = 0;
        (void) abcpwn::commands::fmt::build_write_payload(ws);
    }
    return 0;
}
