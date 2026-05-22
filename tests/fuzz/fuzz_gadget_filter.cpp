// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// libFuzzer harness for the ROP gadget search engine. We wrap the
// fuzzer input as a synthetic ExecutableSection at a fixed VA and
// drive find_gadgets with reasonable bounds. Inputs that decode to
// long gadget sequences are capped via opts.max_depth + max_results
// so any single iteration stays within the libFuzzer time budget.

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/rop_search.hpp"

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size > (64U * 1024U)) {
        return 0;
    }
    abcpwn::commands::rop::ExecutableSection sec;
    sec.name            = ".text";
    sec.virtual_address = 0x400000;
    sec.bytes.assign(data, data + size);

    abcpwn::commands::rop::GadgetSearchOptions opts;
    opts.arch        = abcpwn::arch::Arch::X86_64;
    opts.terminator  = abcpwn::commands::rop::Terminator::Ret;
    opts.max_depth   = 4;
    opts.max_results = 4096;
    (void) abcpwn::commands::rop::find_gadgets(
        std::span<const abcpwn::commands::rop::ExecutableSection>(&sec, 1),
        opts);
    return 0;
}
