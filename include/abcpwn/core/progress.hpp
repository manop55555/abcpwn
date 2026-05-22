// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <memory>
#include <string>

namespace abcpwn::core {

// Thread-safe progress reporter. Long-running commands tick a counter
// from any thread; the reporter renders a single-line indicator
// (overwriting via \r) on stderr when the destination is a TTY. The
// `on_tick` callback is also fired so the JSON renderer can emit
// structured progress events when invoked with --format=json.
class ProgressReporter {
public:
    using TickCallback = std::function<void(std::uint64_t current, std::uint64_t total)>;

    struct Options {
        std::string             label{"working"};
        std::uint64_t           total{0};        // 0 = indeterminate
        std::chrono::milliseconds min_interval{std::chrono::milliseconds{120}};
        bool                    use_stderr{true};
        TickCallback            on_tick{};
    };

    ProgressReporter();
    explicit ProgressReporter(Options opts);
    ~ProgressReporter();

    ProgressReporter(const ProgressReporter&) = delete;
    ProgressReporter& operator=(const ProgressReporter&) = delete;
    ProgressReporter(ProgressReporter&&) = delete;
    ProgressReporter& operator=(ProgressReporter&&) = delete;

    // Add n to the current count. May render to stderr if enough time
    // has passed since the last render.
    void advance(std::uint64_t n = 1);

    // Snapshot of current/total.
    [[nodiscard]] std::uint64_t current() const noexcept;
    [[nodiscard]] std::uint64_t total() const noexcept;

    // Print a final newline on the progress line and stop rendering.
    void finish();

    // Override the output destination (used by tests).
    void set_output(std::ostream* os);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace abcpwn::core
