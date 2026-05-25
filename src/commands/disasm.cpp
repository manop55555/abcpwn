// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/disasm.hpp"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/arch/disasm.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/safe_io.hpp"

namespace abcpwn::commands {

void DisasmCommand::setup(CLI::App& app) {
    app.add_option("input", input, "Hex bytes (default) or file path")->required();
    app.add_option("-a,--arch", arch_name, "Target arch");
    app.add_option("--base-address", base_address, "Base address (hex)");
    app.add_option("--count", max_instructions, "Stop after N instructions (default 1000000)");
    app.add_flag("--input-file{false},--input-hex{true}",
                 input_hex,
                 "Treat input as a hex string (default) or as a file path");
    app.add_flag("--be", big_endian, "Big-endian mode");
    app.add_flag("--thumb", thumb, "ARM thumb encoding");
}

core::Result<core::CommandResult> DisasmCommand::run(const core::Context& ctx) {
    using namespace abcpwn::arch;

    std::vector<std::uint8_t> bytes;
    if (input_hex) {
        auto dec = encoding::hex_decode(input);
        if (!dec) {
            return core::err(dec.error());
        }
        bytes = std::move(*dec);
    } else {
        // Honor ABCPWN_MAX_FILE_SIZE like the other file-reading commands
        // (DEF-13): disasm --input-file previously read any size with rc=0.
        core::safe_io::ReadOptions ropts;
        ropts.max_bytes = ctx.limits.max_file_bytes;
        auto raw = core::safe_io::read_file(input, ropts);
        if (!raw) {
            return core::err(raw.error());
        }
        bytes.reserve(raw->size());
        for (auto b : *raw)
            bytes.push_back(static_cast<std::uint8_t>(b));
    }

    const auto a = arch_from_string(arch_name);
    if (!a) {
        // An unrecognized arch name is malformed input (InvalidInput, 8),
        // not a recognized-but-unimplemented arch (Unsupported, 10) --
        // matches ERROR_CODES.md "--arch passed an unknown architecture
        // name" (DEF-9).
        return core::err(core::ErrorCode::InvalidInput, "disasm: unknown arch '" + arch_name + "'");
    }
    DisasmOptions opts;
    opts.arch = *a;
    // PPC big-endian is the dominant convention (System V PowerOpen ABI,
    // most CTF challenges that ship a PPC binary use BE). Capstone
    // returns an empty decode silently when the byte order is wrong, so
    // a user who typed `disasm --arch ppc64 ...` with the default LE
    // mode just saw an empty output and assumed the bytes were wrong.
    // Default PPC and PPC64 to big-endian; users who actually need LE
    // can opt out with `--be=false` (CLI11 accepts that form for the
    // flag).
    Endian endian = big_endian ? Endian::Big : Endian::Little;
    if (!big_endian && (*a == Arch::Ppc || *a == Arch::Ppc64)) {
        endian = Endian::Big;
    }
    opts.endian = endian;
    opts.thumb_mode = thumb;
    opts.base_address = base_address;
    opts.max_instructions = max_instructions;
    // Internal time budget for the disassembly step. QA round 2
    // OBSERVATION: feeding a multi-MB file through `disasm --input-file`
    // overran the operator's `timeout 30s` wrapper by ~7x because
    // cs_disasm is a single synchronous call that returns only after
    // the entire buffer is decoded. We cannot interrupt cs_disasm
    // mid-flight, but we CAN cap the input size and instruction count
    // applied when neither was set explicitly. The default cap of
    // 1 MiB / 200000 instructions covers typical CTF binaries while
    // keeping the worst case to ~5 seconds on a modest laptop.
    constexpr std::size_t kDefaultByteCap = 1ULL * 1024 * 1024;
    constexpr std::size_t kDefaultInsnCap = 1'000'000;
    const std::size_t original_bytes = bytes.size();
    bool byte_capped = false;
    if (!input_hex && bytes.size() > kDefaultByteCap) {
        bytes.resize(kDefaultByteCap);
        byte_capped = true;
    }
    const bool insn_cap_defaulted = (opts.max_instructions == 0);
    if (insn_cap_defaulted) {
        opts.max_instructions = kDefaultInsnCap;
    }
    const auto deadline_start = std::chrono::steady_clock::now();

    auto insns = disassemble(bytes, opts);
    if (!insns) {
        return core::err(insns.error());
    }

    // Post-disassembly deadline check. Capstone is synchronous, so we
    // can only enforce the budget AFTER cs_disasm returns; the byte-cap
    // above keeps the worst case bounded. If cs_disasm took longer than
    // 30s on the capped input, the user's machine is wedged and the
    // shell wrapper has likely already given up; surface Timeout (exit
    // 15) so automation sees a documented code instead of "process
    // hung but did eventually complete".
    // Default 30s budget, overridable via ABCPWN_DISASM_TIMEOUT_MS (in
    // milliseconds) for tuning on slow hosts and to exercise the Timeout
    // (rc=15) path in tests (DEF-17). Capstone is synchronous, so the
    // check is post-decode; the byte cap above bounds the worst case.
    std::chrono::milliseconds time_budget{30000};
    if (const char* tb = std::getenv("ABCPWN_DISASM_TIMEOUT_MS"); tb != nullptr && *tb != '\0') {
        char* endp = nullptr;
        const auto ms = std::strtoull(tb, &endp, 10);
        if (tb[0] != '-' && endp != tb && *endp == '\0') {
            time_budget = std::chrono::milliseconds{ms};
        }
    }
    const auto elapsed = std::chrono::steady_clock::now() - deadline_start;
    if (elapsed > time_budget) {
        return core::err(core::ErrorCode::Timeout,
                         "disasm: decode exceeded the " + std::to_string(time_budget.count())
                             + " ms time budget");
    }

    // Surface default-cap truncation on stderr (verification N1): the byte
    // cap and the implicit instruction cap previously dropped output with
    // no notice, so users silently got a partial disassembly.
    if (!ctx.quiet()) {
        if (byte_capped) {
            std::fprintf(stderr,
                         "[!] disasm: input truncated to the default %zu-byte cap "
                         "(file is %zu bytes); decoded only the first %zu\n",
                         kDefaultByteCap,
                         original_bytes,
                         kDefaultByteCap);
        }
        if (insn_cap_defaulted && insns->size() >= opts.max_instructions) {
            std::fprintf(stderr,
                         "[!] disasm: output capped at %zu instructions (default); "
                         "pass --count <N> to raise it\n",
                         opts.max_instructions);
        }
    }

    core::CommandResult res;
    for (const auto& ins : *insns) {
        char addr[32];
        std::snprintf(addr, sizeof addr, "0x%lx", (unsigned long) ins.address);
        std::string row = std::string(addr) + ": ";
        const std::string hex = encoding::hex_encode(ins.bytes, " ");
        row.append(hex);
        // Pad bytes column to 24 chars for alignment.
        if (hex.size() < 24) {
            row.append(24 - hex.size(), ' ');
        }
        row.append("  ");
        row.append(ins.text());
        res.raw_lines.push_back(std::move(row));
    }
    return res;
}

} // namespace abcpwn::commands
