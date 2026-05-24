// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/dynelf.hpp"

#include <charconv>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>

#include "abcpwn/commands/encoding.hpp"

namespace abcpwn::commands::dynelf {

namespace {

[[nodiscard]] std::optional<std::uint64_t> parse_hex(std::string_view s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
    }
    std::uint64_t v = 0;
    const auto* e = s.data() + s.size();
    const auto r = std::from_chars(s.data(), e, v, 16);
    if (r.ec != std::errc{} || r.ptr != e) {
        return std::nullopt;
    }
    return v;
}

} // namespace

core::Result<LeakPair> parse_leak_arg(std::string_view s) {
    const auto eq = s.find('=');
    if (eq == std::string_view::npos) {
        return core::err(core::ErrorCode::UsageError, "dynelf: --leak expects <addr>=<hex-bytes>");
    }
    auto addr = parse_hex(s.substr(0, eq));
    if (!addr) {
        return core::err(core::ErrorCode::InvalidInput, "dynelf: --leak address not hex");
    }
    auto bytes = encoding::hex_decode(s.substr(eq + 1));
    if (!bytes) {
        return core::err(bytes.error());
    }
    LeakPair p;
    p.address = *addr;
    p.bytes = std::move(*bytes);
    return p;
}

void DynelfCommand::setup(CLI::App& app) {
    app.add_option("--leak", leaks, "<addr>=<hex-bytes> (repeatable)");
}

core::Result<core::CommandResult> DynelfCommand::run(const core::Context& /*ctx*/) {
    if (leaks.empty()) {
        return core::err(core::ErrorCode::UsageError,
                         "dynelf: at least one --leak <addr>=<hex> required");
    }
    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "leak summary";
    for (const auto& spec : leaks) {
        auto p = parse_leak_arg(spec);
        if (!p) {
            return core::err(p.error());
        }
        char addr_buf[32];
        std::snprintf(addr_buf, sizeof addr_buf, "0x%lx", static_cast<unsigned long>(p->address));
        core::Finding f(core::Severity::Info,
                        std::string(addr_buf),
                        std::to_string(p->bytes.size())
                            + " bytes: " + encoding::hex_encode(p->bytes, " "));
        sec.findings.push_back(std::move(f));
    }
    // libc-db cross-match is not implemented. The honest behavior is to
    // parse the leak pairs into a structured form and stop there;
    // callers feed the result into `abcpwn libc id` (or their own
    // libc-database tooling). The earlier draft of this command shipped
    // a --libc-db flag that did nothing, so it has been removed.
    sec.findings.emplace_back(core::Severity::Info,
                              "note",
                              "leaks parsed; pipe the addresses into `abcpwn libc id` "
                              "or an external libc-database tool to identify the libc");
    return res;
}

} // namespace abcpwn::commands::dynelf
