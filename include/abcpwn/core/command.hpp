// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"

#include <span>
#include <string>
#include <string_view>

// Forward-declare the CLI11 subcommand class so the interface header
// does not pull the full CLI11 include into every command's header.
namespace CLI {
class App;
}  // namespace CLI

namespace abcpwn::core {

// Common shape for every subcommand. Each concrete command implements
// `setup` (to declare CLI flags/positionals on its CLI11 subcommand)
// and `run` (to execute against an already-parsed Context).
class ICommand {
public:
    ICommand() = default;
    ICommand(const ICommand&) = delete;
    ICommand& operator=(const ICommand&) = delete;
    ICommand(ICommand&&) = delete;
    ICommand& operator=(ICommand&&) = delete;
    virtual ~ICommand() = default;

    // Stable name used on the command line ("info", "gadget", ...).
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;

    // One-line description shown in help. No trailing period.
    [[nodiscard]] virtual std::string_view description() const noexcept = 0;

    // Wire flags/positionals onto the CLI11 subcommand. Called once
    // during dispatcher setup, before parsing.
    virtual void setup(CLI::App& app) = 0;

    // Execute. Implementations should respect `ctx.limits` and check
    // for cancellation at coarse intervals.
    [[nodiscard]] virtual Result<CommandResult> run(const Context& ctx) = 0;
};

}  // namespace abcpwn::core
