// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"

#include <iosfwd>
#include <map>
#include <string>
#include <string_view>
#include <variant>

namespace abcpwn::output {

// Schema version emitted in JSON output. Bump per STEP/10 on any
// non-additive change.
inline constexpr int kJsonSchemaVersion = 1;

// Render a CommandResult as the STEP/10 JSON envelope.
class JsonWriter {
public:
    explicit JsonWriter(const core::Context& ctx);

    // Convenience entry point with the typical envelope fields.
    void write(
        std::ostream&                                                  os,
        std::string_view                                               command,
        const core::CommandResult&                                     res,
        const std::map<std::string,
                       std::variant<std::string, std::int64_t, bool>>& args = {}) const;

private:
    const core::Context& ctx_;
};

// Severity name as used in JSON envelope ("info", "low", ...).
[[nodiscard]] std::string_view severity_json_name(core::Severity s) noexcept;

}  // namespace abcpwn::output
