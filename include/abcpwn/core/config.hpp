// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::core::config {

// Supported scalar types in the TOML subset we parse.
using Value = std::variant<std::string, std::int64_t, bool>;

// Parsed configuration: outer key is the table name (default ""),
// inner key is the field. We deliberately keep the data model flat to
// avoid pulling in a full TOML parser; nested tables are not needed by
// any current command's config.
struct Config {
    std::map<std::string, std::map<std::string, Value>> tables{};

    [[nodiscard]] std::optional<std::string> get_string(std::string_view table,
                                                        std::string_view key) const;

    [[nodiscard]] std::optional<std::int64_t> get_int(std::string_view table,
                                                      std::string_view key) const;

    [[nodiscard]] std::optional<bool> get_bool(std::string_view table, std::string_view key) const;
};

// Parse a minimal TOML document. Supported:
//   - `[section]` table headers
//   - `key = "string"`        (double-quoted with backslash escapes \\ \" \n \t)
//   - `key = 'string'`        (single-quoted, literal)
//   - `key = 123`             (signed 64-bit decimal)
//   - `key = 0xCAFE`          (hex)
//   - `key = true` / `false`
//   - `# ...` comments to end of line; blank lines ignored
// Anything else is a parse error with a line/column-tagged message.
[[nodiscard]] Result<Config> parse(std::string_view source);

// Convenience: read + parse from a path. Honors limits via ReadOptions.
[[nodiscard]] Result<Config> load(const std::filesystem::path& path);

// Apply known config keys onto a Context. Unknown keys are silently
// ignored so older binaries can read newer config files.
void apply_to_context(const Config& cfg, Context& ctx);

} // namespace abcpwn::core::config
