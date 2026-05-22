// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace abcpwn::commands::pwn {

enum class TubeKind : std::uint8_t {
    Tcp        = 0,
    UnixSocket = 1,
    Process    = 2,
};

struct TubeSpec {
    TubeKind     kind{TubeKind::Tcp};
    std::string  host_or_path{};   // host for tcp, socket path otherwise
    std::uint16_t port{0};
};

// Parse a target string into a TubeSpec:
//   ./local-binary   -> Process
//   unix:/path       -> UnixSocket
//   host:port        -> Tcp
[[nodiscard]] core::Result<TubeSpec> parse_target(std::string_view target);

enum class DslOp : std::uint8_t {
    RecvUntil  = 0,
    RecvLine   = 1,
    RecvN      = 2,
    Send       = 3,
    SendLine   = 4,
    Sleep      = 5,
    Expect     = 6,
    Set        = 7,
};

struct DslStep {
    DslOp        op{};
    std::string  arg1{};
    std::string  arg2{};
    std::int64_t numeric{0};
};

// Parse the minimal recv/send DSL. Each line is one step; blank lines
// and `#` comments are ignored. Returns InvalidInput on a syntactic
// error pointing at the offending line.
[[nodiscard]] core::Result<std::vector<DslStep>> parse_dsl(std::string_view source);

class PwnCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name()        const noexcept override { return "pwn"; }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "I/O tubes for CTF pwn challenges (TCP / Unix socket)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string  target{};
    std::string  script_path{};
    bool         interactive{false};
    std::string  log_path{};
    std::int64_t timeout_seconds{30};
};

}  // namespace abcpwn::commands::pwn
