// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/phd.hpp"

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/safe_io.hpp"

#include <CLI/CLI.hpp>

#include <cctype>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands {

std::vector<std::string> format_hex_dump(
    std::span<const std::uint8_t> data,
    std::uint64_t                 base_offset,
    std::size_t                   width)
{
    std::vector<std::string> out;
    if (width == 0) {
        width = 16;
    }
    for (std::size_t row = 0; row < data.size(); row += width) {
        char prefix[32];
        std::snprintf(prefix, sizeof prefix, "%08lx",
            static_cast<unsigned long>(base_offset + row));
        std::string line(prefix);
        line.append("  ");

        const std::size_t row_end = std::min(row + width, data.size());
        // Hex column
        for (std::size_t i = row; i < row + width; ++i) {
            if (i < row_end) {
                char buf[4];
                std::snprintf(buf, sizeof buf, "%02x", data[i]);
                line.append(buf);
            } else {
                line.append("  ");
            }
            line.push_back(' ');
            if (i == row + (width / 2) - 1) {
                line.push_back(' ');
            }
        }

        line.push_back('|');
        for (std::size_t i = row; i < row_end; ++i) {
            const unsigned char c = data[i];
            line.push_back((c >= 0x20 && c < 0x7f)
                ? static_cast<char>(c) : '.');
        }
        line.push_back('|');
        out.push_back(std::move(line));
    }
    return out;
}

void PhdCommand::setup(CLI::App& app) {
    app.add_option("input", input, "File path (default) or hex literal")->required();
    app.add_flag("--input-hex{false}", input_file,
        "Treat input as a hex literal instead of a path");
    app.add_option("--offset", offset, "Start offset (decimal or hex)");
    app.add_option("--length", length, "Bytes to dump (0 = all, capped at 4096)");
    app.add_option("--width", width, "Bytes per row (default 16)");
}

core::Result<core::CommandResult> PhdCommand::run(const core::Context& /*ctx*/) {
    std::vector<std::uint8_t> bytes;
    if (input_file) {
        auto raw = core::safe_io::read_file(input);
        if (!raw) {
            return core::err(raw.error());
        }
        bytes.reserve(raw->size());
        for (auto b : *raw) bytes.push_back(static_cast<std::uint8_t>(b));
    } else {
        auto dec = encoding::hex_decode(input);
        if (!dec) {
            return core::err(dec.error());
        }
        bytes = std::move(*dec);
    }

    if (offset > bytes.size()) {
        return core::err(core::ErrorCode::InvalidInput,
            "phd: offset beyond end of data");
    }
    auto window = std::span<const std::uint8_t>(bytes).subspan(static_cast<std::size_t>(offset));

    constexpr std::size_t cap = 4096;
    std::size_t take = (length == 0) ? cap : length;
    if (take > cap) take = cap;
    if (take > window.size()) take = window.size();

    auto rows = format_hex_dump(window.first(take), offset, width);
    core::CommandResult res;
    res.raw_lines = std::move(rows);
    return res;
}

}  // namespace abcpwn::commands
