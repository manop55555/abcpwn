// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/disasm.hpp"

#include <cstdint>
#include <cstdio>
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
    app.add_option("--count", max_instructions, "Stop after N instructions");
    app.add_flag("--input-file{false},--input-hex{true}",
                 input_hex,
                 "Treat input as a hex string (default) or as a file path");
    app.add_flag("--be", big_endian, "Big-endian mode");
    app.add_flag("--thumb", thumb, "ARM thumb encoding");
}

core::Result<core::CommandResult> DisasmCommand::run(const core::Context& /*ctx*/) {
    using namespace abcpwn::arch;

    std::vector<std::uint8_t> bytes;
    if (input_hex) {
        auto dec = encoding::hex_decode(input);
        if (!dec) {
            return core::err(dec.error());
        }
        bytes = std::move(*dec);
    } else {
        auto raw = core::safe_io::read_file(input);
        if (!raw) {
            return core::err(raw.error());
        }
        bytes.reserve(raw->size());
        for (auto b : *raw)
            bytes.push_back(static_cast<std::uint8_t>(b));
    }

    const auto a = arch_from_string(arch_name);
    if (!a) {
        return core::err(core::ErrorCode::Unsupported, "disasm: unknown arch '" + arch_name + "'");
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

    auto insns = disassemble(bytes, opts);
    if (!insns) {
        return core::err(insns.error());
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
