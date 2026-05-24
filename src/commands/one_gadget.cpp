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

core::Result<core::CommandResult> OneGadgetCommand::run(const core::Context& ctx) {
    auto loaded = formats::load(libc, formats::LoadOptions{ctx.limits.max_file_bytes, true});
    if (!loaded) {
        return core::err(loaded.error());
    }
    auto raw =
        core::safe_io::read_file(libc, core::safe_io::ReadOptions{ctx.limits.max_file_bytes, true});
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
    sec.title = "/bin/sh string offsets";

    if (binsh.empty()) {
        sec.findings.emplace_back(core::Severity::Info,
                                  "no /bin/sh string",
                                  "this libc has no execve-shell string at all");
        return res;
    }

    // What this command does today: locate every "/bin/sh\0" inside
    // the libc image and report file offsets. What it does not do:
    // walk back from each lea-to-binsh site to an execve / system
    // call and collect the register and stack preconditions that
    // make that call site reachable. That is the "constraint
    // extraction" half of upstream one_gadget (Ruby) and we do not
    // attempt to fake it here -- callers who need real constraint
    // sets should run the upstream tool against the same libc.
    for (const auto off : binsh) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "0x%lx", (unsigned long) off);
        core::Finding f(core::Severity::Info,
                        std::string("/bin/sh at ") + buf,
                        "string offset; no constraint analysis");
        f.offset = off;
        sec.findings.push_back(std::move(f));
    }
    if (!all) {
        sec.findings.emplace_back(core::Severity::Info,
                                  "note",
                                  "constraint extraction is not implemented; for full one-gadget "
                                  "register/stack constraints, run the upstream one_gadget tool "
                                  "(github.com/david942j/one_gadget) against the same libc");
    }
    return res;
}

} // namespace abcpwn::commands
