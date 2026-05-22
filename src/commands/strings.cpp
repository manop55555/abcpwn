// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/strings.hpp"

#include "abcpwn/core/safe_io.hpp"

#include <CLI/CLI.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands {

namespace {

bool is_printable(unsigned char c) noexcept {
    return (c >= 0x20 && c < 0x7f) || c == '\t';
}

}  // namespace

std::vector<ExtractedString> extract_ascii_strings(
    std::span<const std::uint8_t> data,
    std::size_t                   min_length,
    std::size_t                   max_results)
{
    std::vector<ExtractedString> out;
    out.reserve(std::min<std::size_t>(max_results, 64));

    std::string current;
    std::uint64_t start = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        const unsigned char c = data[i];
        if (is_printable(c)) {
            if (current.empty()) {
                start = static_cast<std::uint64_t>(i);
            }
            current.push_back(static_cast<char>(c));
        } else {
            if (current.size() >= min_length) {
                out.push_back({start, std::move(current)});
                if (out.size() >= max_results) {
                    return out;
                }
            }
            current.clear();
        }
    }
    if (current.size() >= min_length) {
        out.push_back({start, std::move(current)});
    }
    return out;
}

void StringsCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to scan")->required();
    app.add_option("-n,--min-length", min_length, "Minimum string length (default 4)");
    app.add_option("--max-results", max_results, "Cap on number of strings reported");
}

core::Result<core::CommandResult> StringsCommand::run(const core::Context& ctx) {
    core::safe_io::ReadOptions opts;
    opts.max_bytes = ctx.limits.max_file_bytes;
    auto raw = core::safe_io::read_file(target, opts);
    if (!raw) {
        return core::err(raw.error());
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(raw->size());
    for (auto b : *raw) bytes.push_back(static_cast<std::uint8_t>(b));

    auto hits = extract_ascii_strings(bytes, min_length, max_results);
    core::CommandResult res;
    for (const auto& h : hits) {
        char addr[32];
        std::snprintf(addr, sizeof addr, "0x%lx ", (unsigned long) h.offset);
        res.raw_lines.push_back(std::string(addr) + h.value);
    }
    return res;
}

}  // namespace abcpwn::commands
