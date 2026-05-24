// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// pwninit command. Per the project's source-code rules this file is
// one of two allowed to contain network code (the other being libc).
// Network activity is double-gated (compile-time ABCPWN_WITH_NETWORK
// + run-time --allow-network); without it the command lists the
// workflow steps without executing any network ops.

#include "abcpwn/commands/pwninit.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>

namespace abcpwn::commands::pwninit {

void PwninitCommand::setup(CLI::App& app) {
    app.add_option("directory", directory, "Workspace directory (default: current dir)");
    app.add_option("--bin", bin_path, "Challenge binary path");
    app.add_option("--libc", libc_path, "Challenge libc path");
    app.add_option("--ld", ld_path, "Matching ld-linux loader path");
    app.add_option("--template",
                   template_strategy,
                   "Strategy passed to the template command (ret2libc, rop, ...)");
    app.add_flag("--no-patch", no_patch, "Skip the patchelf step (just plan and stop)");
}

namespace {

bool ends_with(std::string_view s, std::string_view suffix) noexcept {
    return s.size() >= suffix.size()
           && s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

} // namespace

core::Result<core::CommandResult> PwninitCommand::run(const core::Context& ctx) {
    core::CommandResult res;
    auto& plan = res.sections.emplace_back();
    plan.title = "pwninit plan";

    // Auto-detect bin / libc / ld if not given by walking `directory`.
    if (bin_path.empty() || libc_path.empty() || ld_path.empty()) {
        std::error_code ec;
        for (const auto& ent : std::filesystem::directory_iterator(directory, ec)) {
            if (!ent.is_regular_file(ec))
                continue;
            const auto p = ent.path().string();
            const auto name = ent.path().filename().string();
            if (libc_path.empty()
                && (ends_with(name, ".so.6") || name.find("libc") != std::string::npos)) {
                libc_path = p;
            } else if (ld_path.empty() && name.find("ld-linux") != std::string::npos) {
                ld_path = p;
            } else if (bin_path.empty()
                       && (ent.status().permissions() & std::filesystem::perms::owner_exec)
                              != std::filesystem::perms::none) {
                bin_path = p;
            }
        }
    }

    plan.findings.emplace_back(
        core::Severity::Info, "binary", bin_path.empty() ? "(not found in directory)" : bin_path);
    plan.findings.emplace_back(
        core::Severity::Info, "libc", libc_path.empty() ? "(not found in directory)" : libc_path);
    plan.findings.emplace_back(core::Severity::Info,
                               "ld-linux",
                               ld_path.empty() ? "(not found; would be downloaded if network)"
                                               : ld_path);

    auto& steps = res.sections.emplace_back();
    steps.title = "steps that would execute";
    if (libc_path.empty()) {
        steps.findings.emplace_back(core::Severity::Info,
                                    "1. identify libc",
                                    "no libc file in directory; would prompt for libc id and "
                                    "download from libc.rip when --allow-network is set");
    } else {
        steps.findings.emplace_back(core::Severity::Info,
                                    "1. identify libc",
                                    "would pipe `abcpwn libc id` with offsets read from the "
                                    "provided libc binary");
    }
    if (ld_path.empty()) {
        const std::string detail =
            network_compiled_in() && ctx.allow_network
                ? "would download matching ld-linux from the libc-database"
                : "would download matching ld-linux (requires --allow-network "
                  "and ABCPWN_WITH_NETWORK build)";
        steps.findings.emplace_back(core::Severity::Info, "2. fetch ld-linux", detail);
    } else {
        steps.findings.emplace_back(
            core::Severity::Info, "2. fetch ld-linux", "ld already present, skip");
    }
    if (no_patch) {
        steps.findings.emplace_back(core::Severity::Info, "3. patchelf", "skipped via --no-patch");
    } else {
        steps.findings.emplace_back(core::Severity::Info,
                                    "3. patchelf",
                                    "would shell out to patchelf to set the binary's interpreter "
                                    "and rpath; pwninit emits the exact command but does not "
                                    "execute it (see project source-code rules on exec*)");
    }
    steps.findings.emplace_back(core::Severity::Info,
                                "4. emit template",
                                "would invoke `abcpwn template " + template_strategy
                                    + "` writing solve.py in the workspace");

    if (!network_compiled_in() || !ctx.allow_network) {
        steps.findings.emplace_back(core::Severity::Medium,
                                    "note",
                                    "this build will not actually download anything: network "
                                    "is not compiled in, or --allow-network was not passed");
    }
    return res;
}

} // namespace abcpwn::commands::pwninit
