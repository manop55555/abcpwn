// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/search.hpp"

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/safe_io.hpp"

#include <CLI/CLI.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace abcpwn::commands {

std::vector<SearchHit> search_bytes(
    std::span<const std::uint8_t> data,
    std::span<const std::uint8_t> needle)
{
    std::vector<SearchHit> out;
    if (needle.empty() || needle.size() > data.size()) {
        return out;
    }
    for (std::size_t i = 0; i + needle.size() <= data.size(); ++i) {
        if (std::equal(needle.begin(), needle.end(), data.begin() + static_cast<std::ptrdiff_t>(i))) {
            out.push_back({static_cast<std::uint64_t>(i), needle.size()});
        }
    }
    return out;
}

void SearchCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to search")->required();
    app.add_option("pattern", pattern, "Pattern (ASCII by default; use -x for hex)")->required();
    app.add_flag("-x,--hex", as_hex, "Treat pattern as hex bytes");
    app.add_flag("-c,--count", count_only, "Show only the count of matches");
}

core::Result<core::CommandResult> SearchCommand::run(const core::Context& ctx) {
    core::safe_io::ReadOptions opts;
    opts.max_bytes = ctx.limits.max_file_bytes;
    auto raw = core::safe_io::read_file(target, opts);
    if (!raw) {
        return core::err(raw.error());
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(raw->size());
    for (auto b : *raw) bytes.push_back(static_cast<std::uint8_t>(b));

    std::vector<std::uint8_t> needle;
    if (as_hex) {
        auto dec = encoding::hex_decode(pattern);
        if (!dec) {
            return core::err(dec.error());
        }
        needle = std::move(*dec);
    } else {
        needle.reserve(pattern.size());
        for (char c : pattern) needle.push_back(static_cast<std::uint8_t>(c));
    }

    const auto hits = search_bytes(bytes, needle);
    core::CommandResult res;
    if (count_only) {
        res.raw_lines.push_back(std::to_string(hits.size()));
        return res;
    }
    for (const auto& h : hits) {
        char buf[64];
        std::snprintf(buf, sizeof buf, "0x%lx (%zu bytes)",
            (unsigned long) h.offset, h.length);
        res.raw_lines.emplace_back(buf);
    }
    if (hits.empty()) {
        res.raw_lines.emplace_back("(no matches)");
    }
    return res;
}

}  // namespace abcpwn::commands
