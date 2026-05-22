// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace abcpwn::commands::shellcode {

enum class Preset : std::uint8_t {
    Sh        = 0,   // execve("/bin/sh", NULL, NULL)
    ReadFlag  = 1,   // open("/flag") + read + write to stdout
    Bind      = 2,   // bind(port) shell
    Reverse   = 3,   // reverse shell to host:port
    CatFlag   = 4,   // cat /flag (variant of ReadFlag)
};

[[nodiscard]] std::optional<Preset> preset_from_string(std::string_view s) noexcept;
[[nodiscard]] std::string_view      preset_name(Preset p) noexcept;

struct PayloadSpec {
    Preset                 preset{Preset::Sh};
    arch::Arch             arch{arch::Arch::X86_64};
    std::uint16_t          bind_port{4444};
    std::string            reverse_host{};
    std::uint16_t          reverse_port{0};
};

struct Encoder {
    enum class Kind : std::uint8_t {
        None      = 0,
        Xor       = 1,
        NullFree  = 2,   // verify-only: refuses payloads that contain 0x00
        Printable = 3,
        Alpha     = 4,
    };
    Kind                       kind{Kind::None};
    std::vector<std::uint8_t>  key{};
};

struct ShellcodePayload {
    arch::Arch                 arch{arch::Arch::X86_64};
    Preset                     preset{Preset::Sh};
    std::vector<std::uint8_t>  bytes{};
    std::string                description{};
    bool                       null_free{false};
};

// Look up a built-in shellcode for the given preset+arch combination.
// Returns Unsupported with a precise message when the combination is
// not in the v0.1 database (the spec calls for ~30 entries; this build
// ships a curated subset and grows over later releases).
[[nodiscard]] core::Result<ShellcodePayload> lookup(const PayloadSpec& spec);

// Apply an encoder to a payload. Some encoders rewrite bytes (Xor);
// others only verify properties (NullFree). Returns the (possibly
// rewritten) bytes plus an Encoder-specific decoder stub when
// applicable.
struct EncodedPayload {
    std::vector<std::uint8_t>  bytes{};
    std::vector<std::uint8_t>  stub{};  // empty for non-rewriting encoders
};

[[nodiscard]] core::Result<EncodedPayload> apply_encoder(
    std::span<const std::uint8_t> input,
    const Encoder&                enc);

// Tiny enumeration of every entry currently in the database. Used by
// tests to assert coverage and by --list output. Never mutated at
// runtime.
[[nodiscard]] std::span<const ShellcodePayload> database() noexcept;

class ShellcodeCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "shellcode"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "emit a built-in shellcode payload, optionally encoded";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string preset_str{"sh"};
    std::string arch_str{"x86_64"};
    std::string encoder_str{"none"};
    std::string xor_key_hex{};
    std::string bad_chars_hex{};
    std::string reverse_addr{};       // "host:port"
    std::uint16_t bind_port{4444};
    std::string format{"hex"};        // hex | raw | c | escaped
    bool        list{false};
};

}  // namespace abcpwn::commands::shellcode
