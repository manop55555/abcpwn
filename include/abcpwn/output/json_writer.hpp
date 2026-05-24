// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <iosfwd>
#include <map>
#include <string>
#include <string_view>
#include <variant>

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::output {

// Schema version emitted in JSON output. Bump on any
// non-additive change.
inline constexpr int kJsonSchemaVersion = 1;

// Render a CommandResult as the JSON envelope.
class JsonWriter {
public:
    explicit JsonWriter(const core::Context& ctx);

    // Convenience entry point with the typical envelope fields.
    void write(std::ostream& os,
               std::string_view command,
               const core::CommandResult& res,
               const std::map<std::string, std::variant<std::string, std::int64_t, bool>>& args =
                   {}) const;

    // Render a failed command as a JSON error envelope (DEF-4): the same
    // top-level shape as write(), with an `error` object {code, name,
    // message} in place of result/findings/summary so a pipeline can
    // parse failures instead of scraping stderr. `message` is expected
    // already stripped of any "<cmd>: " self-prefix by the caller.
    void write_error(std::ostream& os,
                     std::string_view command,
                     int code,
                     std::string_view name,
                     std::string_view message,
                     const std::map<std::string, std::variant<std::string, std::int64_t, bool>>&
                         args = {}) const;

private:
    const core::Context& ctx_;
};

// Severity name as used in JSON envelope ("info", "low", ...).
[[nodiscard]] std::string_view severity_json_name(core::Severity s) noexcept;

} // namespace abcpwn::output
