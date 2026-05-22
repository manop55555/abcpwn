// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::commands::fmt {

// Parse a printf-style hex dump of arguments and locate where a
// marker (default 0x41414141) appears. `dump` is expected to be a
// space-, comma-, dot-, or newline-separated list of hex words, each
// prefixed with "0x" or not. Returns the 1-based argument index or
// nullopt if not found.
[[nodiscard]] std::optional<std::size_t> find_marker_offset(std::string_view dump,
                                                            std::uint64_t marker = 0x41414141ULL);

// Build a payload that leaks the value at format-argument position
// `arg_index`. Returns the payload as a printable string suitable
// for sending to the vulnerable printf.
[[nodiscard]] std::string build_leak_payload(std::size_t arg_index, bool as_string = true);

struct WriteSpec {
    std::uint64_t target_address{0};
    std::uint64_t value{0};
    std::size_t arg_index{0};
    arch::Arch arch{arch::Arch::X86_64};
    std::size_t padding{0};
};

// Build a "what-where" format-string payload (`%n` family) that
// writes `value` to `target_address`. The chosen technique is the
// classic four-byte short-write variant: writes the value as four
// 16-bit chunks via `%hn` to keep the format-string operand counts
// small. Returns the payload bytes.
[[nodiscard]] core::Result<std::vector<std::uint8_t>> build_write_payload(const WriteSpec& spec);

class FmtCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "fmt";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "format string analysis and payload generation";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string find_offset_dump{};
    std::string leak_address_hex{};
    std::string write_spec{}; // "0xADDR=0xVALUE"
    std::int64_t arg_position{-1};
    std::string arch_str{"x86_64"};
    std::size_t start_offset{0};
    std::size_t padding{0};
};

} // namespace abcpwn::commands::fmt
