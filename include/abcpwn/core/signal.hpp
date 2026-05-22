// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <atomic>

namespace abcpwn::core::signal {

// Install handlers for SIGINT/SIGTERM that flip an atomic flag.
// Long-running operations should poll `cancellation_requested()` and
// abort cleanly. Safe to call multiple times; subsequent calls are
// no-ops.
void install_handlers();

// Returns true once a cancellation signal has been received. The flag
// is sticky — once set, it stays set until `reset_for_testing()`.
[[nodiscard]] bool cancellation_requested() noexcept;

// Visible to tests / programmatic callers (e.g., the dispatcher when
// it wraps a sub-operation in its own cancellation scope).
void request_cancellation() noexcept;

// Clear the cancellation flag. Intended for tests only.
void reset_for_testing() noexcept;

// Direct access to the underlying atomic for the few hot loops where
// indirect call overhead matters. Read-only.
[[nodiscard]] const std::atomic<bool>& flag() noexcept;

} // namespace abcpwn::core::signal
