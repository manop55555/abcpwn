// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/output/pretty.hpp"

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <ostream>
#include <string>
#include <string_view>

#include "abcpwn/output/banner.hpp"
#include "abcpwn/output/markers.hpp"

#if defined(__unix__) || defined(__APPLE__)
#include <unistd.h>
#endif

namespace abcpwn::output {

namespace {

[[nodiscard]] bool stream_is_tty(std::ostream& os) noexcept {
#if defined(__unix__) || defined(__APPLE__)
    if (&os == &std::cout)
        return ::isatty(1) != 0;
    if (&os == &std::cerr)
        return ::isatty(2) != 0;
#endif
    (void) os;
    return false;
}

void emit(std::ostream& os, std::string_view a) {
    os.write(a.data(), static_cast<std::streamsize>(a.size()));
}

void maybe_color(std::ostream& os, std::string_view code, bool on) {
    if (on) {
        emit(os, code);
    }
}

constexpr int kSeverityColumn = 60;

[[nodiscard]] std::string severity_tag(core::Severity s) {
    return std::string("[") + std::string(core::severity_name(s)) + "]";
}

[[nodiscard]] std::string fmt_duration(std::chrono::nanoseconds ns) {
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(ns).count();
    return "(" + std::to_string(ms) + " ms)";
}

void print_finding_line(std::ostream& os, const core::Finding& f, bool color) {
    const auto m = marker_for_severity(f.severity);
    std::string left;
    left.reserve(80);
    left.append("    "); // 4-space body indent
    if (color) {
        left.append(color_for_marker(m));
    }
    left.append(m);
    if (color) {
        left.append(Ansi::reset);
    }
    left.push_back(' ');
    left.append(f.title);
    if (!f.detail.empty()) {
        left.append("  ");
        left.append(f.detail);
    }

    // We need the visible width to right-align the severity tag. Track
    // visible width separately from byte length so embedded ANSI codes
    // do not shift the alignment.
    const auto visible_width = static_cast<int>(4 + m.size() + 1 + f.title.size()
                                                + (f.detail.empty() ? 0 : 2 + f.detail.size()));

    emit(os, left);

    if (f.severity != core::Severity::Info) {
        const std::string tag = severity_tag(f.severity);
        const int total_width = visible_width + static_cast<int>(tag.size());
        const int pad = std::max(1, kSeverityColumn - visible_width);
        os << std::string(static_cast<std::size_t>(pad), ' ');
        maybe_color(os, color_for_severity(f.severity), color);
        emit(os, tag);
        maybe_color(os, Ansi::reset, color);
        (void) total_width;
    }
    os << '\n';
}

} // namespace

PrettyPrinter::PrettyPrinter(const core::Context& ctx) : ctx_(ctx) {}

bool PrettyPrinter::should_color(const core::Context& ctx, std::ostream& os) noexcept {
    if (ctx.format == core::OutputFormat::Json)
        return false;
    if (ctx.color == core::ColorMode::Never)
        return false;
    if (const char* nc = std::getenv("NO_COLOR"); nc != nullptr && *nc != '\0') {
        return false;
    }
    if (ctx.color == core::ColorMode::Always)
        return true;
    return stream_is_tty(os);
}

void PrettyPrinter::print_command_header(std::ostream& os) {
    color_active_ = should_color(ctx_, os);
    maybe_color(os, Ansi::dim_white, color_active_);
    emit(os, compact_header());
    maybe_color(os, Ansi::reset, color_active_);
    os << "\n\n";
}

void PrettyPrinter::print_target(std::ostream& os, std::string_view target) {
    emit(os, "  Target: ");
    if (color_active_) {
        emit(os, Ansi::underline);
    }
    emit(os, target);
    if (color_active_) {
        emit(os, Ansi::reset);
    }
    os << "\n\n";
}

void PrettyPrinter::print_section(std::ostream& os, const core::Section& s) {
    if (!s.title.empty()) {
        emit(os, "  ");
        maybe_color(os, Ansi::bold, color_active_);
        emit(os, s.title);
        maybe_color(os, Ansi::reset, color_active_);
        os << '\n';
    }
    for (const auto& f : s.findings) {
        print_finding_line(os, f, color_active_);
    }
}

void PrettyPrinter::print_command_result(std::ostream& os, const core::CommandResult& res) {
    color_active_ = should_color(ctx_, os);

    if (res.raw_payload) {
        // Opaque binary payload: write the bytes as-is with no
        // trailing newline so stdout carries exactly the payload.
        // The dispatcher suppresses the timing footer separately
        // (see print_timing). raw_lines for raw_payload results is
        // expected to be a single entry holding the byte string.
        for (const auto& line : res.raw_lines) {
            os.write(line.data(), static_cast<std::streamsize>(line.size()));
        }
        return;
    }

    for (const auto& s : res.sections) {
        print_section(os, s);
        os << '\n';
    }
    for (const auto& line : res.raw_lines) {
        os << line << '\n';
    }
}

void PrettyPrinter::print_timing(std::ostream& os, const core::CommandResult& res) {
    if (!res.duration || res.raw_payload) {
        return;
    }
    color_active_ = should_color(ctx_, os);
    const std::string d = fmt_duration(*res.duration);
    const int pad = std::max(1, kSeverityColumn - static_cast<int>(d.size()));
    os << std::string(static_cast<std::size_t>(pad), ' ');
    maybe_color(os, Ansi::dim_white, color_active_);
    emit(os, d);
    maybe_color(os, Ansi::reset, color_active_);
    os << '\n';
}

} // namespace abcpwn::output
