// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/gadget.hpp"

#include <cstdint>
#include <cstdio>
#include <span>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/commands/rop_search.hpp"
#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands {

namespace {

rop::Terminator parse_terminator(const std::string& s) noexcept {
    if (s == "jmp")
        return rop::Terminator::Jmp;
    if (s == "call")
        return rop::Terminator::Call;
    if (s == "syscall")
        return rop::Terminator::Syscall;
    if (s == "all")
        return rop::Terminator::All;
    return rop::Terminator::Ret;
}

std::vector<rop::ExecutableSection> collect_executable_sections(const formats::LoadedBinary& lb) {
    std::vector<rop::ExecutableSection> out;
    const auto* binary = lb.binary();
    if (binary == nullptr) {
        return out;
    }
    auto emit = [&](std::string name, std::uint64_t va, std::vector<std::uint8_t> bytes) {
        rop::ExecutableSection s;
        s.name = std::move(name);
        s.virtual_address = va;
        s.bytes = std::move(bytes);
        out.push_back(std::move(s));
    };
    if (const auto* e = dynamic_cast<const LIEF::ELF::Binary*>(binary)) {
        for (const auto& sec : e->sections()) {
            const auto flags = static_cast<std::uint64_t>(sec.flags());
            const auto execflag = static_cast<std::uint64_t>(LIEF::ELF::Section::FLAGS::EXECINSTR);
            if ((flags & execflag) == 0)
                continue;
            const auto raw = sec.content();
            std::vector<std::uint8_t> bytes(raw.begin(), raw.end());
            emit(sec.name(), sec.virtual_address(), std::move(bytes));
        }
    } else if (const auto* p = dynamic_cast<const LIEF::PE::Binary*>(binary)) {
        for (const auto& sec : p->sections()) {
            const auto c = static_cast<std::uint32_t>(sec.characteristics());
            const auto execflag =
                static_cast<std::uint32_t>(LIEF::PE::Section::CHARACTERISTICS::MEM_EXECUTE);
            if ((c & execflag) == 0)
                continue;
            const auto raw = sec.content();
            std::vector<std::uint8_t> bytes(raw.begin(), raw.end());
            emit(sec.name(), sec.virtual_address(), std::move(bytes));
        }
    } else if (const auto* m = dynamic_cast<const LIEF::MachO::Binary*>(binary)) {
        for (const auto& seg : m->segments()) {
            const auto init = static_cast<std::uint32_t>(seg.init_protection());
            if ((init & 0x4) == 0)
                continue; // VM_PROT_EXECUTE
            for (const auto& sec : seg.sections()) {
                const auto raw = sec.content();
                std::vector<std::uint8_t> bytes(raw.begin(), raw.end());
                emit(sec.name(), sec.virtual_address(), std::move(bytes));
            }
        }
    }
    return out;
}

} // namespace

void GadgetCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary to scan")->required();
    app.add_option("-d,--depth", depth, "Max instructions per gadget (default 10)");
    app.add_option("-t,--type", terminator, "ret|jmp|call|syscall|all (default ret)");
    app.add_option("--filter", filter, "Regex applied to gadget text");
    app.add_option("--bad-chars", bad_chars_hex, "Hex bytes to exclude (e.g., 0a00)");
    app.add_option(
        "--max-results", max_results, "Cap on unique gadgets returned (default 1000000)");
    app.add_option("--format", format, "Output format: pretty (others land later)");
    app.add_flag("--no-progress", no_progress, "Suppress stderr progress indicator");
}

core::Result<core::CommandResult> GadgetCommand::run(const core::Context& ctx) {
    auto loaded = formats::load(target, formats::LoadOptions{ctx.limits.max_file_bytes, true});
    if (!loaded) {
        return core::err(loaded.error());
    }
    auto sections = collect_executable_sections(*loaded);
    if (sections.empty()) {
        return core::err(core::ErrorCode::NotFound, "gadget: no executable sections in target");
    }

    const auto a = arch::arch_from_string(loaded->info().arch);
    if (!a) {
        return core::err(core::ErrorCode::Unsupported,
                         "gadget: unknown arch '" + loaded->info().arch + "'");
    }

    if (max_results == 0) {
        return core::err(core::ErrorCode::UsageError, "gadget: --max-results must be > 0");
    }

    rop::GadgetSearchOptions opts;
    opts.arch = *a;
    opts.terminator = parse_terminator(terminator);
    opts.max_depth = depth;
    opts.max_results = max_results;
    opts.text_filter = filter;
    if (!bad_chars_hex.empty()) {
        auto bc = encoding::hex_decode(bad_chars_hex);
        if (!bc) {
            return core::err(bc.error());
        }
        opts.bad_chars = std::move(*bc);
    }

    std::uint64_t total_bytes = 0;
    for (const auto& s : sections)
        total_bytes += s.bytes.size();

    std::optional<core::ProgressReporter> reporter;
    if (!no_progress && !ctx.quiet() && ctx.format != core::OutputFormat::Json) {
        core::ProgressReporter::Options ropts;
        ropts.label = "gadget scan";
        ropts.total = total_bytes;
        ropts.use_stderr = true;
        reporter.emplace(std::move(ropts));
        opts.progress = &*reporter;
    }

    auto gadgets = rop::find_gadgets(sections, opts);
    if (reporter) {
        reporter->finish();
    }
    if (!gadgets) {
        return core::err(gadgets.error());
    }

    if (format != "pretty") {
        return core::err(core::ErrorCode::Unsupported,
                         "gadget: only --format=pretty is implemented in this milestone");
    }

    core::CommandResult res;
    for (const auto& g : *gadgets) {
        char buf[32];
        std::snprintf(buf, sizeof buf, "0x%010lx: ", (unsigned long) g.address);
        res.raw_lines.push_back(std::string(buf) + g.text);
    }
    if (gadgets->empty()) {
        res.raw_lines.emplace_back("(no gadgets matched)");
    }
    char summary[128];
    // The unique-result store stops growing once it hits max_results, so
    // a size exactly equal to the cap is the truncation signal. Surface
    // it on stderr (via a Warning finding) so the user knows raw_lines
    // is an incomplete view of the gadget set and can rerun with a
    // larger --max-results.
    const bool truncated = gadgets->size() >= max_results;
    if (truncated) {
        if (!ctx.quiet()) {
            // The structured finding below lands on stdout in pretty mode;
            // also surface the truncation on stderr so it stays visible when
            // stdout is redirected to a file (verification #17).
            std::fprintf(stderr,
                         "[!] gadget: results truncated at --max-results=%zu; "
                         "rerun with a larger --max-results to see the full set\n",
                         max_results);
        }
        std::snprintf(summary,
                      sizeof summary,
                      "%zu gadgets (truncated at --max-results=%zu; rerun with a larger cap)",
                      gadgets->size(),
                      max_results);
        auto& warn_sec = res.sections.emplace_back();
        warn_sec.title = "warning";
        warn_sec.findings.emplace_back(
            core::Severity::Medium,
            "gadget set truncated",
            "the unique gadget cap was reached; the listed gadgets are the first "
                + std::to_string(max_results)
                + " encountered, not necessarily the best set. Rerun with "
                  "--max-results <N> to raise the cap.");
    } else {
        std::snprintf(summary, sizeof summary, "%zu gadgets", gadgets->size());
    }
    res.summary = summary;
    return res;
}

} // namespace abcpwn::commands
