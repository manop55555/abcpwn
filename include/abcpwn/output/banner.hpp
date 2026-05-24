// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <iosfwd>
#include <string_view>

namespace abcpwn::output {

// Raw verbatim project brand banner. UTF-8, LF line endings.
// Do not mutate, re-align, or insert ANSI codes inside this string;
// color is applied by `print_banner` around the whole block.
[[nodiscard]] std::string_view banner_text() noexcept;

// One-line compact header used above subcommand output.
[[nodiscard]] std::string_view compact_header() noexcept;

// Render the banner to `os`. When `color` is true, the banner is
// wrapped in ANSI color codes (dim white verticals, bold white letters,
// etc.) as a single block.
void print_banner(std::ostream& os, bool color);

} // namespace abcpwn::output
