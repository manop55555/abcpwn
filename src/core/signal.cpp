// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/core/signal.hpp"

#include <atomic>
#include <csignal>

namespace abcpwn::core::signal {

namespace {

std::atomic<bool> g_cancelled{false};
std::atomic_flag g_installed = ATOMIC_FLAG_INIT;

extern "C" void handler(int /*sig*/) {
    g_cancelled.store(true, std::memory_order_release);
}

} // namespace

void install_handlers() {
    if (g_installed.test_and_set(std::memory_order_acq_rel)) {
        return;
    }
    struct sigaction sa{};
    sa.sa_handler = &handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
}

bool cancellation_requested() noexcept {
    return g_cancelled.load(std::memory_order_acquire);
}

void request_cancellation() noexcept {
    g_cancelled.store(true, std::memory_order_release);
}

void reset_for_testing() noexcept {
    g_cancelled.store(false, std::memory_order_release);
}

const std::atomic<bool>& flag() noexcept {
    return g_cancelled;
}

} // namespace abcpwn::core::signal
