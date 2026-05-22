// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>

#include "abcpwn/commands/diff.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/commands/patch.hpp"
#include "abcpwn/core/safe_io.hpp"

namespace abcpwn::commands::diffpatch {

std::vector<ByteDelta> byte_diff(std::span<const std::uint8_t> a, std::span<const std::uint8_t> b) {
    std::vector<ByteDelta> out;
    const std::size_t n = std::min(a.size(), b.size());
    for (std::size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) {
            out.push_back({static_cast<std::uint64_t>(i), a[i], b[i]});
        }
    }
    if (a.size() != b.size()) {
        // append trailing bytes of the longer file as "additions"
        const auto* longer = (a.size() > b.size()) ? a.data() : b.data();
        const std::size_t start = n;
        const std::size_t end = std::max(a.size(), b.size());
        for (std::size_t i = start; i < end; ++i) {
            const std::uint8_t left = (a.size() > b.size()) ? longer[i] : 0;
            const std::uint8_t right = (b.size() > a.size()) ? longer[i] : 0;
            out.push_back({static_cast<std::uint64_t>(i), left, right});
        }
    }
    return out;
}

void DiffCommand::setup(CLI::App& app) {
    app.add_option("file_a", file_a, "Original binary")->required();
    app.add_option("file_b", file_b, "Modified binary")->required();
    app.add_flag("--bytes-only", bytes_only, "Byte-level diff (default)");
    app.add_option(
        "--max-results", max_results, "Cap on number of byte deltas reported (default 1024)");
}

namespace {

std::string hex_str(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%lx", static_cast<unsigned long>(v));
    return std::string(b);
}

} // namespace

core::Result<core::CommandResult> DiffCommand::run(const core::Context& ctx) {
    core::safe_io::ReadOptions opts;
    opts.max_bytes = ctx.limits.max_file_bytes;
    auto a = core::safe_io::read_file(file_a, opts);
    if (!a)
        return core::err(a.error());
    auto b = core::safe_io::read_file(file_b, opts);
    if (!b)
        return core::err(b.error());

    std::vector<std::uint8_t> av(a->size()), bv(b->size());
    for (std::size_t i = 0; i < a->size(); ++i)
        av[i] = static_cast<std::uint8_t>((*a)[i]);
    for (std::size_t i = 0; i < b->size(); ++i)
        bv[i] = static_cast<std::uint8_t>((*b)[i]);

    const auto deltas = byte_diff(av, bv);
    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title =
        "byte diff (" + std::to_string(av.size()) + "/" + std::to_string(bv.size()) + " bytes)";
    std::size_t shown = 0;
    for (const auto& d : deltas) {
        if (shown >= max_results) {
            sec.findings.emplace_back(core::Severity::Info,
                                      "(truncated)",
                                      "+" + std::to_string(deltas.size() - shown)
                                          + " more deltas; raise --max-results to show all");
            break;
        }
        char a_buf[8], b_buf[8];
        std::snprintf(a_buf, sizeof a_buf, "0x%02x", d.a);
        std::snprintf(b_buf, sizeof b_buf, "0x%02x", d.b);
        sec.findings.emplace_back(
            core::Severity::Info, hex_str(d.offset), std::string(a_buf) + " -> " + b_buf);
        ++shown;
    }
    if (deltas.empty()) {
        sec.findings.emplace_back(core::Severity::Info, "(identical)", "no byte deltas");
    }
    res.summary = std::to_string(deltas.size()) + " byte deltas";
    return res;
}

void PatchCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to patch")->required();
    app.add_option("--byte", byte_patches, "Repeatable: offset=hex (e.g., 0x100=90909090)");
    app.add_option("--nop", nop_patches, "Repeatable: offset:count (NOP out N bytes from offset)");
    app.add_flag("--in-place", in_place, "Patch the original in place (default: writes .patched)");
    app.add_flag("--backup{true},--no-backup{false}",
                 backup,
                 "When --in-place, write a .bak first (default true)");
}

namespace {

[[nodiscard]] core::Result<std::uint64_t> parse_hex_or_dec(std::string_view s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        std::uint64_t v = 0;
        const auto* begin = s.data() + 2;
        const auto* end = s.data() + s.size();
        const auto r = std::from_chars(begin, end, v, 16);
        if (r.ec != std::errc{} || r.ptr != end) {
            return core::err(core::ErrorCode::InvalidInput,
                             "patch: bad hex literal '" + std::string(s) + "'");
        }
        return v;
    }
    std::uint64_t v = 0;
    const auto r = std::from_chars(s.data(), s.data() + s.size(), v);
    if (r.ec != std::errc{} || r.ptr != s.data() + s.size()) {
        return core::err(core::ErrorCode::InvalidInput,
                         "patch: bad numeric literal '" + std::string(s) + "'");
    }
    return v;
}

} // namespace

core::Result<core::CommandResult> PatchCommand::run(const core::Context& ctx) {
    core::safe_io::ReadOptions opts;
    opts.max_bytes = ctx.limits.max_file_bytes;
    auto raw = core::safe_io::read_file(target, opts);
    if (!raw)
        return core::err(raw.error());
    std::vector<std::uint8_t> bytes(raw->size());
    for (std::size_t i = 0; i < raw->size(); ++i) {
        bytes[i] = static_cast<std::uint8_t>((*raw)[i]);
    }

    auto apply_byte = [&](std::uint64_t off,
                          const std::vector<std::uint8_t>& payload) -> core::Result<void> {
        if (off + payload.size() > bytes.size()) {
            return core::err(core::ErrorCode::InvalidInput, "patch: byte patch beyond end of file");
        }
        for (std::size_t i = 0; i < payload.size(); ++i) {
            bytes[off + i] = payload[i];
        }
        return {};
    };

    for (const auto& spec : byte_patches) {
        const auto eq = spec.find('=');
        if (eq == std::string::npos) {
            return core::err(core::ErrorCode::UsageError, "patch: --byte expects offset=hex");
        }
        auto off = parse_hex_or_dec(std::string_view(spec).substr(0, eq));
        if (!off)
            return core::err(off.error());
        auto pay = encoding::hex_decode(std::string_view(spec).substr(eq + 1));
        if (!pay)
            return core::err(pay.error());
        if (auto r = apply_byte(*off, *pay); !r) {
            return core::err(r.error());
        }
    }
    for (const auto& spec : nop_patches) {
        const auto col = spec.find(':');
        if (col == std::string::npos) {
            return core::err(core::ErrorCode::UsageError, "patch: --nop expects offset:count");
        }
        auto off = parse_hex_or_dec(std::string_view(spec).substr(0, col));
        if (!off)
            return core::err(off.error());
        auto cnt = parse_hex_or_dec(std::string_view(spec).substr(col + 1));
        if (!cnt)
            return core::err(cnt.error());
        if (*off + *cnt > bytes.size()) {
            return core::err(core::ErrorCode::InvalidInput, "patch: --nop beyond end of file");
        }
        for (std::uint64_t i = 0; i < *cnt; ++i) {
            bytes[*off + i] = 0x90; // x86 NOP; users on other arches
                                    // can use --byte with explicit hex.
        }
    }

    const std::string out_path = in_place ? target : target + ".patched";

    if (in_place && backup) {
        const std::span<const std::byte> src(raw->data(), raw->size());
        if (auto w = core::safe_io::write_file_atomic(target + ".bak", src); !w) {
            return core::err(w.error());
        }
    }
    if (auto w = core::safe_io::write_file_atomic(
            out_path,
            std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()),
                                       bytes.size()));
        !w) {
        return core::err(w.error());
    }

    core::CommandResult res;
    res.raw_lines.push_back("wrote " + std::to_string(bytes.size()) + " bytes to " + out_path);
    res.summary = std::to_string(byte_patches.size()) + " byte patches, "
                  + std::to_string(nop_patches.size()) + " NOP patches";
    return res;
}

} // namespace abcpwn::commands::diffpatch
