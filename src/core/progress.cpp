// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/core/progress.hpp"

#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <ostream>
#include <string>

#if defined(__unix__) || defined(__APPLE__)
#  include <unistd.h>
#endif

namespace abcpwn::core {

namespace {

[[nodiscard]] bool stderr_is_tty() noexcept {
#if defined(__unix__) || defined(__APPLE__)
    return ::isatty(2) != 0;
#else
    return false;
#endif
}

}  // namespace

struct ProgressReporter::Impl {
    Options                                     opts;
    std::atomic<std::uint64_t>                  current{0};
    std::mutex                                  render_mu;
    std::chrono::steady_clock::time_point       last_render{};
    bool                                        finished{false};
    bool                                        ever_rendered{false};
    std::ostream*                               output{nullptr};

    Impl() : output(&std::cerr) {}

    [[nodiscard]] bool should_render(std::chrono::steady_clock::time_point now) const {
        if (!ever_rendered) {
            return true;
        }
        return (now - last_render) >= opts.min_interval;
    }

    void render(std::uint64_t cur) {
        if (output == nullptr) {
            return;
        }
        std::ostream& os = *output;
        // Carriage-return-only when stderr is a TTY; for non-TTY (test
        // capture, redirected output) emit newline-terminated lines.
        const bool tty = (output == &std::cerr) && stderr_is_tty();
        os << '\r' << "[*] " << opts.label << ": " << cur;
        if (opts.total > 0) {
            os << " / " << opts.total;
            const auto pct = (opts.total == 0) ? 0
                : static_cast<int>((cur * 100) / opts.total);
            os << " (" << pct << "%)";
        }
        if (tty) {
            os << "        " << std::flush;
        } else {
            os << '\n';
        }
    }
};

ProgressReporter::ProgressReporter() : impl_(std::make_unique<Impl>()) {}

ProgressReporter::ProgressReporter(Options opts) : impl_(std::make_unique<Impl>()) {
    impl_->opts = std::move(opts);
}

ProgressReporter::~ProgressReporter() {
    if (impl_) {
        finish();
    }
}

void ProgressReporter::advance(std::uint64_t n) {
    if (!impl_ || impl_->finished) return;
    const auto now_cur = impl_->current.fetch_add(n, std::memory_order_acq_rel) + n;
    if (impl_->opts.on_tick) {
        impl_->opts.on_tick(now_cur, impl_->opts.total);
    }
    if (!impl_->opts.use_stderr) {
        return;
    }
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lk(impl_->render_mu);
    if (impl_->should_render(now)) {
        impl_->render(now_cur);
        impl_->last_render = now;
        impl_->ever_rendered = true;
    }
}

std::uint64_t ProgressReporter::current() const noexcept {
    return impl_ ? impl_->current.load(std::memory_order_acquire) : 0;
}

std::uint64_t ProgressReporter::total() const noexcept {
    return impl_ ? impl_->opts.total : 0;
}

void ProgressReporter::finish() {
    if (!impl_ || impl_->finished) return;
    std::scoped_lock lk(impl_->render_mu);
    if (impl_->ever_rendered && impl_->output != nullptr && impl_->opts.use_stderr) {
        *impl_->output << '\n';
    }
    impl_->finished = true;
}

void ProgressReporter::set_output(std::ostream* os) {
    if (!impl_) return;
    impl_->output = os;
}

}  // namespace abcpwn::core
