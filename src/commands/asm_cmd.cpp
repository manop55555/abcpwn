// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/asm_cmd.hpp"

#include <cstdint>
#include <span>
#include <sstream>
#include <string>

#include <CLI/CLI.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/arch/asm.hpp"
#include "abcpwn/commands/encoding.hpp"

namespace abcpwn::commands {

void AsmCommand::setup(CLI::App& app) {
    app.add_option("source", source, "Assembly source")->required();
    app.add_option("-a,--arch", arch_name, "Target arch (x86_64, arm, aarch64, ...)");
    app.add_option("--base-address", base_address, "Base address (hex)");
    app.add_flag("--be", big_endian, "Big-endian mode");
    app.add_flag("--thumb", thumb, "ARM thumb encoding");
    app.add_option("--format", format, "hex | raw | escaped | c");
}

core::Result<core::CommandResult> AsmCommand::run(const core::Context& /*ctx*/) {
    using namespace abcpwn::arch;
    const auto a = arch_from_string(arch_name);
    if (!a) {
        return core::err(core::ErrorCode::Unsupported, "asm: unknown arch '" + arch_name + "'");
    }
    AsmOptions opts;
    opts.arch = *a;
    opts.endian = big_endian ? Endian::Big : Endian::Little;
    opts.thumb_mode = thumb;
    opts.base_address = base_address;

    auto bytes = assemble(source, opts);
    if (!bytes) {
        return core::err(bytes.error());
    }

    core::CommandResult res;
    const std::span<const std::uint8_t> view(*bytes);
    if (format == "raw") {
        res.raw_lines.emplace_back(reinterpret_cast<const char*>(view.data()), view.size());
    } else if (format == "escaped") {
        std::string s;
        s.reserve(view.size() * 4);
        for (auto b : view) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\x%02x", b);
            s.append(buf);
        }
        res.raw_lines.push_back(std::move(s));
    } else if (format == "c") {
        std::ostringstream os;
        os << "unsigned char shellcode[" << view.size() << "] = {";
        for (std::size_t i = 0; i < view.size(); ++i) {
            if (i > 0)
                os << ", ";
            char buf[8];
            std::snprintf(buf, sizeof buf, "0x%02x", view[i]);
            os << buf;
        }
        os << "};";
        res.raw_lines.push_back(os.str());
    } else {
        res.raw_lines.push_back(encoding::hex_encode(view));
    }
    return res;
}

} // namespace abcpwn::commands
