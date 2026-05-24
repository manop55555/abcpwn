// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "abcpwn/core/context.hpp"

namespace spdlog {
class logger;
} // namespace spdlog

namespace abcpwn::output {

// Centralized logger setup. Idempotent: subsequent calls reconfigure
// the existing logger rather than allocate a new one.
//
// Configuration sources, in order of precedence (highest first):
//   1. ctx.log_file       -> file sink under that path
//   2. ctx.verbosity      -> level (-q=warn, default=info, -v=debug, -vv=trace)
//   3. STDERR             -> always present as a colored console sink in pretty
//                            mode; disabled when ctx.format == Json to keep
//                            machine-readable output clean.
void setup_logging(const core::Context& ctx);

// Return the project-wide logger. Creates a no-op fallback if
// setup_logging() has not yet been called, so callers never get nullptr.
[[nodiscard]] std::shared_ptr<spdlog::logger> get_logger();

// Emit a debug-level message through the project logger. Visible only at
// -v / -vv (debug/trace) and never in JSON mode. Wraps spdlog so callers
// (e.g. the dispatcher) need not pull in spdlog headers.
void log_debug(std::string_view message);

// Convenience accessor for tests; returns the last log file path
// configured (empty if logging only goes to stderr).
[[nodiscard]] const std::string& last_log_path_for_testing();

} // namespace abcpwn::output
