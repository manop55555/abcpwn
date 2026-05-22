// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/one_gadget.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/commands/search.hpp"
#include "abcpwn/core/safe_io.hpp"
#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands {

namespace {

// Locate every occurrence of the literal "/bin/sh" inside a flat
// byte buffer. Returns file offsets.
std::vector<std::uint64_t> find_binsh(std::span<const std::uint8_t> data) {
    static constexpr std::uint8_t needle[] = {
        '/',
        'b',
        'i',
        'n',
        '/',
        's',
        'h',
        0,
    };
    auto hits = search_bytes(data, std::span<const std::uint8_t>(needle, sizeof needle));
    std::vector<std::uint64_t> out;
    out.reserve(hits.size());
    for (const auto& h : hits)
        out.push_back(h.offset);
    return out;
}

} // namespace

void OneGadgetCommand::setup(CLI::App& app) {
    app.add_option("libc", libc, "libc image to analyze")->required();
    app.add_flag("--all", all, "Show all candidates (default: filter to highest-confidence)");
}

core::Result<core::CommandResult> OneGadgetCommand::run(const core::Context& /*ctx*/) {
    auto loaded = formats::load(libc);
    if (!loaded) {
        return core::err(loaded.error());
    }
    auto raw = core::safe_io::read_file(libc);
    if (!raw) {
        return core::err(raw.error());
    }
    std::vector<std::uint8_t> bytes;
    bytes.reserve(raw->size());
    for (auto b : *raw)
        bytes.push_back(static_cast<std::uint8_t>(b));

    const auto binsh = find_binsh(bytes);

    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "one-gadget candidates";

    if (binsh.empty()) {
        sec.findings.emplace_back(
            core::Severity::Info, "no /bin/sh string", "no execve-shell candidates");
        return res;
    }

    // v0.1 stub: report each "/bin/sh" offset as a candidate landmark
    // and note that constraint extraction is deferred. A full
    // implementation would: find lea-to-binsh sites, walk back to
    // the nearest execve syscall / __execve / system call site, and
    // collect register / stack constraints. That requires
    // symbolic-execution-lite analysis and lands in a later
    // milestone -- this scaffold preserves the spec's command
    // shape (the libc / address fields) without faking the analysis.
    for (const auto off : binsh) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "0x%lx", (unsigned long) off);
        core::Finding f(core::Severity::Info,
                        std::string("/bin/sh at ") + buf,
                        "constraints: not analyzed in this milestone (v0.1 stub)");
        f.offset = off;
        sec.findings.push_back(std::move(f));
    }
    if (!all) {
        sec.findings.emplace_back(
            core::Severity::Info,
            "note",
            "true one-gadget constraint extraction lands in a future version; "
            "in the meantime use the offsets above with manual disassembly");
    }
    return res;
}

} // namespace abcpwn::commands
