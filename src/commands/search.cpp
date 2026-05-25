// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/search.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/safe_io.hpp"
#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands {

std::vector<SearchHit> search_bytes(std::span<const std::uint8_t> data,
                                    std::span<const std::uint8_t> needle) {
    std::vector<SearchHit> out;
    if (needle.empty() || needle.size() > data.size()) {
        return out;
    }
    for (std::size_t i = 0; i + needle.size() <= data.size(); ++i) {
        if (std::equal(
                needle.begin(), needle.end(), data.begin() + static_cast<std::ptrdiff_t>(i))) {
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

namespace {

std::string hex_u64(std::uint64_t v) {
    char buf[20];
    std::snprintf(buf, sizeof buf, "0x%llx", static_cast<unsigned long long>(v));
    return buf;
}

} // namespace

core::Result<core::CommandResult> SearchCommand::run(const core::Context& ctx) {
    core::safe_io::ReadOptions opts;
    opts.max_bytes = ctx.limits.max_file_bytes;
    auto raw = core::safe_io::read_file(target, opts);
    if (!raw) {
        return core::err(raw.error());
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(raw->size());
    for (auto b : *raw)
        bytes.push_back(static_cast<std::uint8_t>(b));

    std::vector<std::uint8_t> needle;
    if (as_hex) {
        auto dec = encoding::hex_decode(pattern);
        if (!dec) {
            return core::err(dec.error());
        }
        needle = std::move(*dec);
    } else {
        needle.reserve(pattern.size());
        for (char c : pattern)
            needle.push_back(static_cast<std::uint8_t>(c));
    }

    const auto hits = search_bytes(bytes, needle);
    core::CommandResult res;
    if (count_only) {
        res.raw_lines.push_back(std::to_string(hits.size()));
        return res;
    }

    // Map file offsets to virtual addresses + sections for known formats
    // (DEF-6). Raw / unknown input keeps file offsets only (vaddr = null).
    // require_known_format=false: a non-binary file simply yields no
    // structure rather than an error.
    auto loaded = formats::load(target, formats::LoadOptions{ctx.limits.max_file_bytes, false});
    LIEF::Binary* bin = loaded ? loaded->binary() : nullptr;

    auto& sec = res.sections.emplace_back();
    sec.title = "Matches";
    for (const auto& h : hits) {
        std::optional<std::uint64_t> vaddr;
        std::string section;
        if (bin != nullptr) {
            for (const auto& s : bin->sections()) {
                const std::uint64_t soff = s.offset();
                const std::uint64_t ssize = s.size();
                if (ssize != 0 && h.offset >= soff && h.offset < soff + ssize) {
                    section = s.name();
                    if (s.virtual_address() != 0) {
                        vaddr = s.virtual_address() + (h.offset - soff);
                    }
                    break;
                }
            }
        }

        core::Finding f(core::Severity::Info, hex_u64(h.offset));
        f.offset = h.offset;
        std::string detail;
        if (vaddr) {
            detail = "vaddr " + hex_u64(*vaddr);
            f.extra["vaddr"] = hex_u64(*vaddr);
        }
        if (!section.empty()) {
            if (!detail.empty()) {
                detail += "  ";
            }
            detail += "section " + section;
            f.extra["section"] = section;
        }
        if (!detail.empty()) {
            detail += "  ";
        }
        detail += "(" + std::to_string(h.length) + " bytes)";
        f.detail = std::move(detail);
        sec.findings.push_back(std::move(f));
    }
    if (hits.empty()) {
        sec.findings.emplace_back(core::Severity::Info, "(no matches)");
    }
    res.summary = std::to_string(hits.size()) + " matches";
    return res;
}

} // namespace abcpwn::commands
