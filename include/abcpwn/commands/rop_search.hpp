// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/arch/disasm.hpp"
#include "abcpwn/core/progress.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::commands::rop {

enum class Terminator : std::uint8_t {
    Ret = 0,
    Jmp = 1,
    Call = 2,
    Syscall = 3,
    All = 4,
};

struct ExecutableSection {
    std::string name{};
    std::uint64_t virtual_address{0};
    std::vector<std::uint8_t> bytes{};
};

struct Gadget {
    std::uint64_t address{0};
    std::vector<std::uint8_t> bytes{};
    std::string text{}; // "pop rdi ; ret"
};

struct GadgetSearchOptions {
    arch::Arch arch{arch::Arch::X86_64};
    Terminator terminator{Terminator::Ret};
    std::size_t max_depth{10};
    std::vector<std::uint8_t> bad_chars{};
    std::string text_filter{}; // regex
    std::size_t max_results{200'000};
    core::ProgressReporter* progress{nullptr};
};

// Find ROP gadgets in the provided executable sections. For each
// terminator byte, slides backwards trying start offsets; each start
// position whose forward disassembly ends exactly on the terminator
// is emitted as a gadget. Deduplication keeps the lowest-VA copy of
// each unique gadget text; results are sorted by address ascending.
[[nodiscard]] core::Result<std::vector<Gadget>>
find_gadgets(std::span<const ExecutableSection> sections, const GadgetSearchOptions& opts);

// Convenience helper: extract executable sections from a loaded
// binary into the shape `find_gadgets` consumes.
struct LoadedBinaryRef; // forward; the actual implementation includes
                        // the formats header in the .cpp.

} // namespace abcpwn::commands::rop
