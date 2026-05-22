// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/aslr_bypass.hpp"

#include <CLI/CLI.hpp>

#include <cstdint>
#include <string>

namespace abcpwn::commands::aslr_bypass {

void AslrBypassCommand::setup(CLI::App& app) {
    app.add_flag("--partial-overwrite", partial_overwrite,
        "Describe 1/2-byte partial-overwrite technique");
    app.add_flag("--brute-force", brute_force,
        "Report expected brute-force attempts");
    app.add_flag("--canary-leak", canary_leak,
        "Print a canary-leak template");
    app.add_option("--entropy-bits", entropy_bits,
        "ASLR entropy bits for brute-force estimation (default 28)");
}

core::Result<core::CommandResult> AslrBypassCommand::run(const core::Context& /*ctx*/) {
    if (!partial_overwrite && !brute_force && !canary_leak) {
        return core::err(core::ErrorCode::UsageError,
            "aslr-bypass: pick one of --partial-overwrite, --brute-force, --canary-leak");
    }
    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "ASLR bypass strategy";

    if (partial_overwrite) {
        sec.findings.emplace_back(core::Severity::Info, "technique",
            "1/2-byte partial overwrite of saved RIP / return address");
        sec.findings.emplace_back(core::Severity::Info, "applicability",
            "works when ASLR randomizes the high bits but the low 1-2 "
            "bytes of the target call site are stable");
        sec.findings.emplace_back(core::Severity::Info, "recipe",
            "leak a high-byte adjacent code address, then overwrite "
            "only the low byte(s) of the saved RIP to redirect to a "
            "nearby gadget within the same page");
    }
    if (brute_force) {
        const std::uint64_t attempts = (entropy_bits >= 64)
            ? std::uint64_t(-1)
            : (std::uint64_t(1) << entropy_bits);
        sec.findings.emplace_back(core::Severity::Info, "entropy",
            std::to_string(entropy_bits) + " bits");
        sec.findings.emplace_back(core::Severity::Info, "expected attempts",
            std::to_string(attempts / 2));   // mean of geometric distribution
        sec.findings.emplace_back(core::Severity::Info, "worst case",
            std::to_string(attempts));
        sec.findings.emplace_back(core::Severity::Medium, "viability",
            entropy_bits >= 20
              ? "brute force is impractical without fork-server behavior"
              : "brute force may be tractable with a fork-server target");
    }
    if (canary_leak) {
        sec.findings.emplace_back(core::Severity::Info, "template",
            "use format-string `%N$p` over the canary slot, then "
            "construct a buffer that overwrites the return address "
            "while preserving the canary value");
        sec.findings.emplace_back(core::Severity::Info, "x86_64 detail",
            "stack canary is typically at [rbp - 0x8]; first byte is 0x00 "
            "to prevent string-based leaks via strcpy/strcat");
    }
    return res;
}

}  // namespace abcpwn::commands::aslr_bypass
