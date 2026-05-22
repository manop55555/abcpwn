// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// libc command. Per CLAUDE.md this file is one of two source files
// allowed to contain network code (the other being pwninit). Network
// access is additionally compile-time gated by ABCPWN_WITH_NETWORK
// and run-time gated by --allow-network on the context.

#include "abcpwn/commands/libc.hpp"

#include <CLI/CLI.hpp>

#include <array>
#include <charconv>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#if defined(ABCPWN_WITH_NETWORK) && ABCPWN_WITH_NETWORK
#  include <curl/curl.h>
#endif

namespace abcpwn::commands::libc {

namespace {

// Tiny offline knowledge base of glibc fingerprints. The full
// libc-database is megabytes; the v0.1 in-binary table is just the
// most-asked entries CTF players hit. Symbol offsets are from the
// libc base (rather than absolute), per pwntools convention.
struct Fingerprint {
    std::string_view  id;
    std::string_view  symbol;
    std::uint64_t     offset;
};

constexpr std::array<Fingerprint, 18> kFingerprints = {{
    {"libc6_2.27-3ubuntu1.6_amd64", "system",     0x55410},
    {"libc6_2.27-3ubuntu1.6_amd64", "execve",     0xe62f0},
    {"libc6_2.27-3ubuntu1.6_amd64", "puts",       0x80f50},
    {"libc6_2.27-3ubuntu1.6_amd64", "printf",     0x64f00},
    {"libc6_2.27-3ubuntu1.6_amd64", "__libc_start_main_ret", 0x21b97},

    {"libc6_2.31-0ubuntu9.16_amd64", "system",    0x52290},
    {"libc6_2.31-0ubuntu9.16_amd64", "execve",    0xe40a0},
    {"libc6_2.31-0ubuntu9.16_amd64", "puts",      0x84420},
    {"libc6_2.31-0ubuntu9.16_amd64", "printf",    0x61c90},
    {"libc6_2.31-0ubuntu9.16_amd64", "__libc_start_main_ret", 0x270b3},

    {"libc6_2.34-0ubuntu3_amd64", "system",       0x4f550},
    {"libc6_2.34-0ubuntu3_amd64", "execve",       0xebd30},
    {"libc6_2.34-0ubuntu3_amd64", "puts",         0x80450},
    {"libc6_2.34-0ubuntu3_amd64", "printf",       0x607f0},
    {"libc6_2.34-0ubuntu3_amd64", "__libc_start_main_ret", 0x29d90},

    {"libc6_2.39-0ubuntu8_amd64", "system",       0x50d70},
    {"libc6_2.39-0ubuntu8_amd64", "execve",       0xebb00},
    {"libc6_2.39-0ubuntu8_amd64", "puts",         0x80e50},
}};

[[nodiscard]] std::optional<std::uint64_t> parse_hex(std::string_view s) {
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        s.remove_prefix(2);
    }
    std::uint64_t v = 0;
    const auto* end = s.data() + s.size();
    const auto r = std::from_chars(s.data(), end, v, 16);
    if (r.ec != std::errc{} || r.ptr != end) {
        return std::nullopt;
    }
    return v;
}

// Returns the candidate IDs that fit ALL provided (symbol, low-12-bit
// offset) pairs. We match on the low 12 bits because libc base
// addresses are page-aligned and ASLR randomizes everything else.
struct OffsetPair {
    std::string   symbol;
    std::uint16_t low12;
};

[[nodiscard]] std::vector<std::string> identify_libc(
    const std::vector<OffsetPair>& pairs)
{
    std::vector<std::string> candidates;
    // Walk every known ID and keep ones that match every input pair.
    std::set<std::string_view> all_ids;
    for (const auto& fp : kFingerprints) all_ids.insert(fp.id);

    for (const auto& id : all_ids) {
        bool all_match = true;
        for (const auto& want : pairs) {
            bool found_one = false;
            for (const auto& fp : kFingerprints) {
                if (fp.id != id || fp.symbol != want.symbol) continue;
                if ((fp.offset & 0xfff) == want.low12) {
                    found_one = true;
                    break;
                }
            }
            if (!found_one) { all_match = false; break; }
        }
        if (all_match) candidates.emplace_back(id);
    }
    return candidates;
}

[[nodiscard]] std::string hex_str(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%lx", static_cast<unsigned long>(v));
    return std::string(b);
}

}  // namespace

void LibcCommand::setup(CLI::App& app) {
    app.add_option("action", action,
        "id | offsets | diff | download | search")->required();
    app.add_option("--offset", offset_pairs,
        "For 'id': repeatable sym:hex pair. For others: ignored.");
    app.add_option("--symbol", symbol,
        "For 'offsets': filter to one symbol");
    app.add_option("id", identifier,
        "libc identifier (offsets / download / search)");
    app.add_option("--other", other,
        "Second libc id for 'diff'");
}

core::Result<core::CommandResult> LibcCommand::run(const core::Context& ctx) {
    core::CommandResult res;

    if (action == "id") {
        std::vector<OffsetPair> pairs;
        for (const auto& spec : offset_pairs) {
            const auto colon = spec.find(':');
            if (colon == std::string::npos) {
                return core::err(core::ErrorCode::UsageError,
                    "libc id: --offset expects sym:hex (e.g., puts:0xe50)");
            }
            const std::string sym(spec.begin(), spec.begin() + colon);
            const auto off = parse_hex(spec.substr(colon + 1));
            if (!off) {
                return core::err(core::ErrorCode::InvalidInput,
                    "libc id: offset for '" + sym + "' not hex");
            }
            OffsetPair p;
            p.symbol = sym;
            p.low12  = static_cast<std::uint16_t>(*off & 0xfffU);
            pairs.push_back(std::move(p));
        }
        if (pairs.empty()) {
            return core::err(core::ErrorCode::UsageError,
                "libc id: provide at least one --offset sym:hex");
        }
        const auto hits = identify_libc(pairs);
        auto& sec = res.sections.emplace_back();
        sec.title = "libc id candidates";
        for (const auto& id : hits) {
            sec.findings.emplace_back(core::Severity::Info, "match", id);
        }
        if (hits.empty()) {
            sec.findings.emplace_back(core::Severity::Info, "(none)",
                "no libc in the v0.1 in-binary table matches these offsets; "
                "download a fuller libc-database for broader coverage");
        }
        return res;
    }

    if (action == "offsets") {
        if (identifier.empty()) {
            return core::err(core::ErrorCode::UsageError,
                "libc offsets: pass a libc id (positional)");
        }
        auto& sec = res.sections.emplace_back();
        sec.title = "offsets in " + identifier;
        for (const auto& fp : kFingerprints) {
            if (fp.id != identifier) continue;
            if (!symbol.empty() && fp.symbol != symbol) continue;
            sec.findings.emplace_back(core::Severity::Info,
                std::string(fp.symbol), hex_str(fp.offset));
        }
        if (sec.findings.empty()) {
            return core::err(core::ErrorCode::NotFound,
                "libc offsets: no entries for '" + identifier
                + (symbol.empty() ? "" : "' / symbol '" + symbol)
                + "'");
        }
        return res;
    }

    if (action == "diff") {
        if (identifier.empty() || other.empty()) {
            return core::err(core::ErrorCode::UsageError,
                "libc diff: pass id and --other id");
        }
        auto& sec = res.sections.emplace_back();
        sec.title = "diff " + identifier + " vs " + other;
        std::map<std::string_view, std::uint64_t> a_map, b_map;
        for (const auto& fp : kFingerprints) {
            if (fp.id == identifier) a_map[fp.symbol] = fp.offset;
            if (fp.id == other)      b_map[fp.symbol] = fp.offset;
        }
        for (const auto& [sym, off] : a_map) {
            if (auto it = b_map.find(sym); it != b_map.end()) {
                const auto delta = static_cast<std::int64_t>(it->second)
                                 - static_cast<std::int64_t>(off);
                char buf[64];
                std::snprintf(buf, sizeof buf, "%s -> %s   (delta %+ld)",
                    hex_str(off).c_str(), hex_str(it->second).c_str(),
                    static_cast<long>(delta));
                sec.findings.emplace_back(core::Severity::Info,
                    std::string(sym), buf);
            }
        }
        return res;
    }

    if (action == "download") {
        if (!ctx.allow_network) {
            return core::err(core::ErrorCode::NetworkDisabled,
                "libc download: --allow-network not set on Context");
        }
        if (!network_compiled_in()) {
            return core::err(core::ErrorCode::FeatureDisabled,
                "libc download: this build was compiled without "
                "ABCPWN_WITH_NETWORK. Rebuild with "
                "-DABCPWN_WITH_NETWORK=ON or use the abcpwn-full "
                "release artifact.");
        }
#if defined(ABCPWN_WITH_NETWORK) && ABCPWN_WITH_NETWORK
        if (identifier.empty()) {
            return core::err(core::ErrorCode::UsageError,
                "libc download: pass a libc id (positional)");
        }
        // libc-database compatible URL pattern; the upstream project
        // serves a per-id tarball at this layout.
        const std::string url =
            "https://libc.rip/api/libs/" + identifier;
        CURL* curl = curl_easy_init();
        if (curl == nullptr) {
            return core::err(core::ErrorCode::NetworkError,
                "libc download: curl_easy_init() failed");
        }
        long http_code = 0;
        std::string body;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
            +[](char* ptr, size_t s, size_t n, void* userdata) -> size_t {
                auto* out = static_cast<std::string*>(userdata);
                out->append(ptr, s * n);
                return s * n;
            });
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
        const auto rc = curl_easy_perform(curl);
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
        if (rc != CURLE_OK) {
            return core::err(core::ErrorCode::NetworkError,
                std::string("libc download: ") + curl_easy_strerror(rc));
        }
        auto& sec = res.sections.emplace_back();
        sec.title = "libc download";
        sec.findings.emplace_back(core::Severity::Info, "url", url);
        sec.findings.emplace_back(core::Severity::Info, "http",
            std::to_string(http_code));
        sec.findings.emplace_back(core::Severity::Info, "bytes",
            std::to_string(body.size()));
        return res;
#else
        return core::err(core::ErrorCode::FeatureDisabled,
            "libc download: network not compiled in");
#endif
    }

    if (action == "search") {
        if (identifier.empty()) {
            return core::err(core::ErrorCode::UsageError,
                "libc search: pass a pattern");
        }
        auto& sec = res.sections.emplace_back();
        sec.title = "search '" + identifier + "'";
        std::set<std::string_view> ids;
        for (const auto& fp : kFingerprints) {
            if (fp.id.find(identifier) != std::string_view::npos) {
                ids.insert(fp.id);
            }
        }
        for (const auto& id : ids) {
            sec.findings.emplace_back(core::Severity::Info,
                std::string(id), "match");
        }
        if (ids.empty()) {
            sec.findings.emplace_back(core::Severity::Info, "(no match)",
                "v0.1 in-binary table has no entries containing '"
                + identifier + "'");
        }
        return res;
    }

    return core::err(core::ErrorCode::UsageError,
        "libc: unknown action '" + action + "'");
}

}  // namespace abcpwn::commands::libc
