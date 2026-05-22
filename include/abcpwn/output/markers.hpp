// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <string_view>

#include "abcpwn/core/error.hpp"

namespace abcpwn::output {

// ASCII status markers (STEP/02). The tokens here are the only
// pre-colon glyphs allowed in any abcpwn output.
struct Marker {
    static constexpr std::string_view ok = "[+]";
    static constexpr std::string_view bad = "[-]";
    static constexpr std::string_view warn = "[!]";
    static constexpr std::string_view info = "[*]";
    static constexpr std::string_view question = "[?]";
};

// ANSI SGR sequences. Keep the set small so the renderer is easy to
// audit. Bracketed names match the STEP/02 color rules.
struct Ansi {
    static constexpr std::string_view reset = "\x1b[0m";
    static constexpr std::string_view bold = "\x1b[1m";
    static constexpr std::string_view dim = "\x1b[2m";
    static constexpr std::string_view underline = "\x1b[4m";
    static constexpr std::string_view red = "\x1b[31m";
    static constexpr std::string_view green = "\x1b[32m";
    static constexpr std::string_view yellow = "\x1b[33m";
    static constexpr std::string_view cyan = "\x1b[36m";
    static constexpr std::string_view magenta = "\x1b[35m";
    static constexpr std::string_view white = "\x1b[37m";
    static constexpr std::string_view orange_256 = "\x1b[38;5;208m";
    static constexpr std::string_view bold_red = "\x1b[1;31m";
    static constexpr std::string_view bold_yellow = "\x1b[1;33m";
    static constexpr std::string_view dim_cyan = "\x1b[2;36m";
    static constexpr std::string_view dim_white = "\x1b[2;37m";
};

[[nodiscard]] constexpr std::string_view marker_for_severity(core::Severity s) noexcept {
    switch (s) {
    case core::Severity::Info:
        return Marker::info;
    case core::Severity::Low:
        return Marker::warn;
    case core::Severity::Medium:
        return Marker::warn;
    case core::Severity::High:
        return Marker::bad;
    case core::Severity::Critical:
        return Marker::bad;
    }
    return Marker::info;
}

[[nodiscard]] constexpr std::string_view color_for_severity(core::Severity s) noexcept {
    switch (s) {
    case core::Severity::Info:
        return Ansi::cyan;
    case core::Severity::Low:
        return Ansi::yellow;
    case core::Severity::Medium:
        return Ansi::orange_256;
    case core::Severity::High:
        return Ansi::red;
    case core::Severity::Critical:
        return Ansi::bold_red;
    }
    return Ansi::cyan;
}

[[nodiscard]] constexpr std::string_view color_for_marker(std::string_view m) noexcept {
    if (m == Marker::ok)
        return Ansi::green;
    if (m == Marker::bad)
        return Ansi::red;
    if (m == Marker::warn)
        return Ansi::yellow;
    if (m == Marker::info)
        return Ansi::cyan;
    if (m == Marker::question)
        return Ansi::magenta;
    return Ansi::reset;
}

} // namespace abcpwn::output
