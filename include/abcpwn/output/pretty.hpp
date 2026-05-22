// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"

#include <iosfwd>
#include <string>
#include <string_view>

namespace abcpwn::output {

// Render a CommandResult to a stream as pretty-formatted output, per
// STEP/10. Honors STEP/02 color rules: colors only when stdout is a
// TTY, NO_COLOR is unset, --no-color is not passed, and format is
// pretty (not json). For tests, the caller can force color via the
// context.
class PrettyPrinter {
public:
    explicit PrettyPrinter(const core::Context& ctx);

    // Decide whether color is applied for `os` based on ctx + TTY +
    // NO_COLOR env. Visible for tests.
    [[nodiscard]] static bool should_color(
        const core::Context& ctx,
        std::ostream&        os) noexcept;

    void print_command_header(std::ostream& os);
    void print_target(std::ostream& os, std::string_view target);
    void print_section(std::ostream& os, const core::Section& s);
    void print_command_result(std::ostream& os, const core::CommandResult& res);

private:
    const core::Context& ctx_;
    bool                 color_active_{false};
};

}  // namespace abcpwn::output
