// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/core/config.hpp"

#include "abcpwn/core/safe_io.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstddef>
#include <string>
#include <string_view>

namespace abcpwn::core::config {

namespace {

struct Cursor {
    std::string_view text;
    std::size_t      pos{0};
    std::size_t      line{1};

    [[nodiscard]] bool eof() const noexcept { return pos >= text.size(); }
    [[nodiscard]] char peek() const noexcept {
        return pos < text.size() ? text[pos] : '\0';
    }
};

[[nodiscard]] bool is_key_char(char c) noexcept {
    const auto u = static_cast<unsigned char>(c);
    return std::isalnum(u) != 0 || c == '_' || c == '-' || c == '.';
}

void skip_inline_ws(Cursor& cur) {
    while (!cur.eof()) {
        const char c = cur.peek();
        if (c == ' ' || c == '\t') {
            ++cur.pos;
        } else {
            break;
        }
    }
}

void advance_line(Cursor& cur) {
    while (!cur.eof() && cur.text[cur.pos] != '\n') {
        ++cur.pos;
    }
    if (!cur.eof()) {
        ++cur.pos;
        ++cur.line;
    }
}

Error make_parse_error(const Cursor& cur, std::string_view msg) {
    return Error{
        ErrorCode::InvalidInput,
        std::string("config: line ") + std::to_string(cur.line) + ": " + std::string(msg),
    };
}

Result<std::string> parse_string(Cursor& cur) {
    const char quote = cur.peek();
    if (quote != '"' && quote != '\'') {
        return err(make_parse_error(cur, "expected quoted string"));
    }
    ++cur.pos;
    std::string out;
    out.reserve(16);
    const bool literal = (quote == '\'');
    while (!cur.eof()) {
        const char c = cur.text[cur.pos];
        if (c == quote) {
            ++cur.pos;
            return out;
        }
        if (c == '\n') {
            return err(make_parse_error(cur, "unterminated string"));
        }
        if (!literal && c == '\\') {
            if (cur.pos + 1 >= cur.text.size()) {
                return err(make_parse_error(cur, "trailing backslash"));
            }
            const char esc = cur.text[cur.pos + 1];
            switch (esc) {
                case '"':  out.push_back('"');  break;
                case '\\': out.push_back('\\'); break;
                case 'n':  out.push_back('\n'); break;
                case 't':  out.push_back('\t'); break;
                case 'r':  out.push_back('\r'); break;
                case '0':  out.push_back('\0'); break;
                default:
                    return err(make_parse_error(cur,
                        std::string("unknown escape '\\") + esc + "'"));
            }
            cur.pos += 2;
        } else {
            out.push_back(c);
            ++cur.pos;
        }
    }
    return err(make_parse_error(cur, "unterminated string"));
}

Result<Value> parse_value(Cursor& cur) {
    skip_inline_ws(cur);
    if (cur.eof()) {
        return err(make_parse_error(cur, "expected value"));
    }
    const char c = cur.peek();
    if (c == '"' || c == '\'') {
        auto s = parse_string(cur);
        if (!s) {
            return err(s.error());
        }
        return Value{*s};
    }
    if (c == 't' || c == 'f') {
        const auto remaining = cur.text.substr(cur.pos);
        if (remaining.starts_with("true")) {
            cur.pos += 4;
            return Value{true};
        }
        if (remaining.starts_with("false")) {
            cur.pos += 5;
            return Value{false};
        }
    }
    if (c == '-' || c == '+' || (std::isdigit(static_cast<unsigned char>(c)) != 0)) {
        const std::size_t start = cur.pos;
        if (c == '-' || c == '+') {
            ++cur.pos;
        }
        int base = 10;
        if (cur.pos + 1 < cur.text.size()
            && cur.text[cur.pos] == '0'
            && (cur.text[cur.pos + 1] == 'x' || cur.text[cur.pos + 1] == 'X'))
        {
            base = 16;
            cur.pos += 2;
        }
        while (!cur.eof()) {
            const char d = cur.text[cur.pos];
            const auto ud = static_cast<unsigned char>(d);
            if (base == 16 && std::isxdigit(ud) == 0) break;
            if (base == 10 && std::isdigit(ud) == 0) break;
            ++cur.pos;
        }
        std::int64_t val = 0;
        const auto* begin = cur.text.data() + start;
        const auto* end   = cur.text.data() + cur.pos;
        // std::from_chars does not accept a leading + in the input; if we
        // saw one, advance past it for parsing only.
        if (*begin == '+') {
            ++begin;
        }
        // Hex prefix is also not accepted by from_chars; trim and set base.
        if (base == 16) {
            // Skip "[+-]0x" (we already moved past it)
            begin = cur.text.data() + start;
            if (*begin == '+' || *begin == '-') ++begin;
            begin += 2;  // skip 0x
        }
        const auto conv = std::from_chars(begin, end, val, base);
        if (conv.ec != std::errc{} || conv.ptr != end) {
            cur.pos = start;
            return err(make_parse_error(cur, "invalid integer literal"));
        }
        // Re-apply sign if hex parsing dropped it.
        if (base == 16 && cur.text[start] == '-') {
            val = -val;
        }
        return Value{val};
    }
    return err(make_parse_error(cur, "unrecognized value"));
}

}  // namespace

std::optional<std::string> Config::get_string(
    std::string_view table, std::string_view key) const
{
    const auto t = tables.find(std::string(table));
    if (t == tables.end()) return std::nullopt;
    const auto k = t->second.find(std::string(key));
    if (k == t->second.end()) return std::nullopt;
    if (const auto* s = std::get_if<std::string>(&k->second)) return *s;
    return std::nullopt;
}

std::optional<std::int64_t> Config::get_int(
    std::string_view table, std::string_view key) const
{
    const auto t = tables.find(std::string(table));
    if (t == tables.end()) return std::nullopt;
    const auto k = t->second.find(std::string(key));
    if (k == t->second.end()) return std::nullopt;
    if (const auto* v = std::get_if<std::int64_t>(&k->second)) return *v;
    return std::nullopt;
}

std::optional<bool> Config::get_bool(
    std::string_view table, std::string_view key) const
{
    const auto t = tables.find(std::string(table));
    if (t == tables.end()) return std::nullopt;
    const auto k = t->second.find(std::string(key));
    if (k == t->second.end()) return std::nullopt;
    if (const auto* v = std::get_if<bool>(&k->second)) return *v;
    return std::nullopt;
}

Result<Config> parse(std::string_view source) {
    Config cfg;
    std::string current_table;
    Cursor cur{source, 0, 1};

    while (!cur.eof()) {
        skip_inline_ws(cur);
        if (cur.eof()) break;

        const char c = cur.peek();
        if (c == '\n') {
            ++cur.pos;
            ++cur.line;
            continue;
        }
        if (c == '#') {
            advance_line(cur);
            continue;
        }
        if (c == '[') {
            ++cur.pos;
            const std::size_t name_start = cur.pos;
            while (!cur.eof() && cur.peek() != ']' && cur.peek() != '\n') {
                ++cur.pos;
            }
            if (cur.eof() || cur.peek() == '\n') {
                return err(make_parse_error(cur, "unterminated table header"));
            }
            current_table = std::string(
                cur.text.substr(name_start, cur.pos - name_start));
            // trim whitespace
            const auto first = current_table.find_first_not_of(" \t");
            const auto last  = current_table.find_last_not_of(" \t");
            if (first == std::string::npos) {
                return err(make_parse_error(cur, "empty table header"));
            }
            current_table = current_table.substr(first, last - first + 1);
            ++cur.pos;  // skip ']'
            // optional trailing comment / whitespace
            skip_inline_ws(cur);
            if (!cur.eof() && cur.peek() == '#') {
                advance_line(cur);
            } else if (!cur.eof() && cur.peek() == '\n') {
                ++cur.pos;
                ++cur.line;
            } else if (!cur.eof()) {
                return err(make_parse_error(cur, "trailing content after table header"));
            }
            continue;
        }
        // key = value
        const std::size_t key_start = cur.pos;
        while (!cur.eof() && is_key_char(cur.peek())) {
            ++cur.pos;
        }
        if (cur.pos == key_start) {
            return err(make_parse_error(cur, "expected key"));
        }
        const std::string key(cur.text.substr(key_start, cur.pos - key_start));
        skip_inline_ws(cur);
        if (cur.eof() || cur.peek() != '=') {
            return err(make_parse_error(cur, "expected '=' after key"));
        }
        ++cur.pos;
        auto v = parse_value(cur);
        if (!v) {
            return err(v.error());
        }
        cfg.tables[current_table].insert_or_assign(key, *v);
        skip_inline_ws(cur);
        if (!cur.eof() && cur.peek() == '#') {
            advance_line(cur);
        } else if (!cur.eof() && cur.peek() == '\n') {
            ++cur.pos;
            ++cur.line;
        } else if (!cur.eof()) {
            return err(make_parse_error(cur, "trailing content after value"));
        }
    }
    return cfg;
}

Result<Config> load(const std::filesystem::path& path) {
    safe_io::ReadOptions opts;
    opts.max_bytes = 1ULL << 20;  // 1 MiB cap for config
    auto text = safe_io::read_text_file(path, opts);
    if (!text) {
        return err(text.error());
    }
    return parse(*text);
}

void apply_to_context(const Config& cfg, Context& ctx) {
    if (auto v = cfg.get_bool("output", "allow_network")) {
        ctx.allow_network = *v;
    }
    if (auto v = cfg.get_bool("output", "no_banner")) {
        ctx.no_banner = *v;
    }
    if (auto v = cfg.get_string("output", "color")) {
        if (*v == "always") {
            ctx.color = ColorMode::Always;
        } else if (*v == "never") {
            ctx.color = ColorMode::Never;
        } else if (*v == "auto") {
            ctx.color = ColorMode::Auto;
        }
    }
    if (auto v = cfg.get_string("output", "format")) {
        if (*v == "json") {
            ctx.format = OutputFormat::Json;
        } else if (*v == "pretty") {
            ctx.format = OutputFormat::Pretty;
        }
    }
    if (auto v = cfg.get_int("limits", "max_file_bytes"); v && *v > 0) {
        ctx.limits.max_file_bytes = static_cast<std::size_t>(*v);
    }
    if (auto v = cfg.get_int("limits", "max_runtime_seconds"); v && *v > 0) {
        ctx.limits.max_runtime = std::chrono::seconds{*v};
    }
    if (auto v = cfg.get_int("limits", "max_threads"); v && *v >= 0) {
        ctx.limits.max_threads = static_cast<std::uint32_t>(*v);
    }
}

}  // namespace abcpwn::core::config
