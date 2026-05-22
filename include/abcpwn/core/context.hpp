// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>

namespace abcpwn::core {

enum class OutputFormat : std::uint8_t {
    Pretty = 0,
    Json = 1,
};

enum class ColorMode : std::uint8_t {
    Auto = 0,
    Always = 1,
    Never = 2,
};

// Resource limits applied to operations that consume large inputs.
// See STEP/12_RESOURCE_LIMITS.md for the rationale; the values here
// are conservative defaults that commands may tighten further per
// invocation.
struct Limits {
    std::size_t max_file_bytes{static_cast<std::size_t>(2) * 1024 * 1024 * 1024}; // 2 GiB
    std::size_t max_section_bytes{256ULL * 1024 * 1024};                          // 256 MiB
    std::size_t max_string_chars{8ULL * 1024 * 1024};                             // 8 MiB
    std::size_t max_gadget_results{500'000};
    std::chrono::seconds max_runtime{std::chrono::seconds{900}}; // 15 min
    std::uint32_t max_threads{0};                                // 0 = auto
};

// Global execution context threaded into every command. Anything that
// might vary per invocation lives here; do not stash state in static
// globals.
struct Context {
    OutputFormat format{OutputFormat::Pretty};
    ColorMode color{ColorMode::Auto};
    int verbosity{0}; // -v adds 1, -q subtracts
    bool allow_network{false};
    bool no_banner{false};
    Limits limits{};
    std::filesystem::path config_path{};   // optional config TOML
    std::filesystem::path cwd{};           // captured at startup
    std::optional<std::string> log_file{}; // optional spdlog file sink

    [[nodiscard]] bool quiet() const noexcept {
        return verbosity < 0;
    }
    [[nodiscard]] bool debug() const noexcept {
        return verbosity >= 2;
    }
};

} // namespace abcpwn::core
