// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/shellcode.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/encoding.hpp"

namespace abcpwn::commands::shellcode {

namespace {

[[nodiscard]] bool contains_byte(std::span<const std::uint8_t> data, std::uint8_t b) noexcept {
    for (auto v : data) {
        if (v == b)
            return true;
    }
    return false;
}

} // namespace

core::Result<EncodedPayload> apply_encoder(std::span<const std::uint8_t> input,
                                           const Encoder& enc) {
    EncodedPayload out;
    switch (enc.kind) {
    case Encoder::Kind::None:
        out.bytes.assign(input.begin(), input.end());
        return out;
    case Encoder::Kind::NullFree:
        if (contains_byte(input, 0x00)) {
            return core::err(core::ErrorCode::InvalidInput,
                             "shellcode: payload contains 0x00 (null-free verification failed)");
        }
        out.bytes.assign(input.begin(), input.end());
        return out;
    case Encoder::Kind::Xor: {
        if (enc.key.empty()) {
            return core::err(core::ErrorCode::InvalidInput,
                             "shellcode: --encoder xor requires --xor-key <hex>");
        }
        out.bytes = encoding::xor_with_key(input, enc.key);
        // The decoder stub is not generated in this milestone; the
        // command surface accepts XOR encoding so callers can XOR
        // a payload for bad-character avoidance even when they
        // intend to manually prepend a decoder.
        return out;
    }
    case Encoder::Kind::Printable:
    case Encoder::Kind::Alpha:
        return core::err(core::ErrorCode::Unsupported,
                         "shellcode: encoder not implemented in this milestone "
                         "(printable / alpha land in a subsequent release)");
    }
    return core::err(core::ErrorCode::InvalidInput, "shellcode: unknown encoder kind");
}

namespace {

std::string format_hex(std::span<const std::uint8_t> bytes) {
    return encoding::hex_encode(bytes);
}

std::string format_escaped(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(bytes.size() * 4);
    for (auto b : bytes) {
        char buf[8];
        std::snprintf(buf, sizeof buf, "\\x%02x", b);
        out.append(buf);
    }
    return out;
}

std::string format_c(std::span<const std::uint8_t> bytes) {
    std::ostringstream os;
    os << "unsigned char shellcode[" << bytes.size() << "] = {";
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0)
            os << ", ";
        char buf[8];
        std::snprintf(buf, sizeof buf, "0x%02x", bytes[i]);
        os << buf;
    }
    os << "};";
    return os.str();
}

} // namespace

void ShellcodeCommand::setup(CLI::App& app) {
    // The v0.1 shellcode database ships only `sh` across the
    // three supported arches. `read-flag` / `cat-flag` / `bind` /
    // `reverse` were advertised in the choice list but not in
    // the database; they returned ErrorCode::Unsupported when
    // called. Choice list trimmed to what actually works (QA
    // round 1 MAJOR).
    app.add_option("-p,--preset", preset_str, "sh");
    app.add_option("-a,--arch", arch_str, "x86_64 (default) | x86 | aarch64");
    // null-free and xor are implemented; printable + alpha return
    // ErrorCode::Unsupported and are removed from the choice list
    // until they ship.
    app.add_option("-e,--encoder", encoder_str, "none (default) | null-free | xor");
    app.add_option(
        "--xor-key", xor_key_hex, "Hex bytes of the XOR key (required when --encoder xor)");
    app.add_option("--bad-chars", bad_chars_hex, "Hex bytes to exclude from the final payload");
    // --reverse-addr / --bind-port removed (QA round 1 MAJOR
    // stubs). The `reverse` and `bind` presets themselves are
    // also not in the v0.1 database; only `sh` ships across the
    // three supported arches. Network shellcode presets return
    // in v0.2.
    // The per-subcommand encoding selector is named --output-format
    // to avoid colliding with the global --format (which selects
    // pretty/json output of the *whole* command result). Both flags
    // can be combined: `--format json --output-format hex` emits
    // JSON whose `raw_lines[0]` is the hex string.
    app.add_option("--output-format", format, "hex (default) | raw | c | escaped");
    app.add_flag("--list", list, "List the built-in database and exit");
}

core::Result<core::CommandResult> ShellcodeCommand::run(const core::Context& /*ctx*/) {
    if (list) {
        core::CommandResult res;
        auto& sec = res.sections.emplace_back();
        sec.title = "shellcode database";
        for (const auto& e : database()) {
            core::Finding f(core::Severity::Info,
                            std::string(arch::arch_name(e.arch)) + " / "
                                + std::string(preset_name(e.preset)),
                            std::to_string(e.bytes.size()) + " bytes  " + e.description);
            sec.findings.push_back(std::move(f));
        }
        return res;
    }

    const auto preset = preset_from_string(preset_str);
    if (!preset) {
        return core::err(core::ErrorCode::UsageError,
                         "shellcode: unknown preset '" + preset_str + "'");
    }
    const auto a = arch::arch_from_string(arch_str);
    if (!a) {
        return core::err(core::ErrorCode::UsageError, "shellcode: unknown arch '" + arch_str + "'");
    }

    PayloadSpec spec;
    spec.preset = *preset;
    spec.arch = *a;
    spec.bind_port = bind_port;
    // host:port parsing is intentionally deferred -- the reverse
    // preset is not in the v0.1 database yet, so callers won't reach
    // a code path that needs the parsed parts.
    spec.reverse_host = reverse_addr;

    auto payload = lookup(spec);
    if (!payload) {
        return core::err(payload.error());
    }

    Encoder enc;
    if (encoder_str == "none") {
        enc.kind = Encoder::Kind::None;
    } else if (encoder_str == "null-free") {
        enc.kind = Encoder::Kind::NullFree;
    } else if (encoder_str == "xor") {
        enc.kind = Encoder::Kind::Xor;
        auto k = encoding::hex_decode(xor_key_hex);
        if (!k) {
            return core::err(k.error());
        }
        enc.key = std::move(*k);
    } else if (encoder_str == "printable") {
        enc.kind = Encoder::Kind::Printable;
    } else if (encoder_str == "alpha") {
        enc.kind = Encoder::Kind::Alpha;
    } else {
        return core::err(core::ErrorCode::UsageError,
                         "shellcode: unknown encoder '" + encoder_str + "'");
    }

    auto encoded = apply_encoder(payload->bytes, enc);
    if (!encoded) {
        return core::err(encoded.error());
    }

    // Bad-char filter: reject the (encoded) payload if it contains any
    // listed byte. The XOR encoder is what callers normally use to
    // avoid bad chars; this check confirms the result.
    if (!bad_chars_hex.empty()) {
        auto bc = encoding::hex_decode(bad_chars_hex);
        if (!bc) {
            return core::err(bc.error());
        }
        for (auto b : *bc) {
            if (contains_byte(encoded->bytes, b)) {
                char buf[8];
                std::snprintf(buf, sizeof buf, "0x%02x", b);
                return core::err(core::ErrorCode::InvalidInput,
                                 std::string("shellcode: encoded payload contains bad byte ")
                                     + buf);
            }
        }
    }

    core::CommandResult res;
    if (format == "raw") {
        res.raw_lines.emplace_back(reinterpret_cast<const char*>(encoded->bytes.data()),
                                   encoded->bytes.size());
        // Opaque binary; suppress banner + timing footer on
        // stdout so the payload bytes are unpolluted.
        res.raw_payload = true;
    } else if (format == "c") {
        res.raw_lines.push_back(format_c(encoded->bytes));
    } else if (format == "escaped") {
        res.raw_lines.push_back(format_escaped(encoded->bytes));
    } else {
        // hex (default)
        res.raw_lines.push_back(format_hex(encoded->bytes));
    }
    res.summary = std::to_string(encoded->bytes.size()) + " bytes ("
                  + std::string(preset_name(*preset)) + " on " + std::string(arch::arch_name(*a))
                  + ")";
    return res;
}

} // namespace abcpwn::commands::shellcode
