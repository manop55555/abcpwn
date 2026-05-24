// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/rop.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/rop_search.hpp"
#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands {

namespace {

std::vector<rop::ExecutableSection> collect_executable_sections(const formats::LoadedBinary& lb) {
    std::vector<rop::ExecutableSection> out;
    const auto* binary = lb.binary();
    if (binary == nullptr) {
        return out;
    }
    if (const auto* e = dynamic_cast<const LIEF::ELF::Binary*>(binary)) {
        for (const auto& sec : e->sections()) {
            const auto flags = static_cast<std::uint64_t>(sec.flags());
            const auto execflag = static_cast<std::uint64_t>(LIEF::ELF::Section::FLAGS::EXECINSTR);
            if ((flags & execflag) == 0)
                continue;
            const auto raw = sec.content();
            std::vector<std::uint8_t> bytes(raw.begin(), raw.end());
            rop::ExecutableSection s;
            s.name = sec.name();
            s.virtual_address = sec.virtual_address();
            s.bytes = std::move(bytes);
            out.push_back(std::move(s));
        }
    }
    return out;
}

[[nodiscard]] std::optional<rop::Gadget> find_gadget_text_eq(std::span<const rop::Gadget> gadgets,
                                                             std::string_view text) noexcept {
    for (const auto& g : gadgets) {
        if (g.text == text)
            return g;
    }
    return std::nullopt;
}

// Result of fuzzy-matching a "pop <reg> ; ... ; ret" gadget. `padding`
// is the number of EXTRA stack slots the chain must fill (one per
// intermediate pop) between this gadget's value slot and the next
// gadget address. Zero means "exact match, no extra slots".
struct FuzzyPop {
    rop::Gadget gadget;
    std::size_t padding{0};
};

// Conservative fuzzy match for syscall-chain construction.
//
// Accepts gadgets of the form:
//     pop <target_reg> ; (pop <safe_reg> ; )* ret
//
// where every intermediate pop targets a register OUTSIDE
// `forbidden`. forbidden is the set of registers the caller plans
// to populate via other gadgets in the chain; clobbering them
// here would break the chain. Returns the SHORTEST acceptable
// gadget (fewest intermediate pops). Exact match wins.
[[nodiscard]] std::optional<FuzzyPop>
find_pop_gadget(std::span<const rop::Gadget> gadgets,
                std::string_view target_reg,
                std::span<const std::string_view> forbidden) noexcept {
    std::optional<FuzzyPop> best;
    const std::string exact = std::string{"pop "} + std::string{target_reg} + " ; ret";

    for (const auto& g : gadgets) {
        std::string_view t = g.text;
        if (!t.ends_with(" ; ret") && t != "ret") {
            continue;
        }
        std::string_view body = t;
        if (body.ends_with(" ; ret")) {
            body.remove_suffix(6); // strip " ; ret"
        }

        // Walk semicolon-separated instructions; require every one to
        // be "pop <reg>", first one must be the target.
        std::vector<std::string_view> parts;
        std::size_t pos = 0;
        while (pos < body.size()) {
            const auto sep = body.find(" ; ", pos);
            const auto end = (sep == std::string_view::npos) ? body.size() : sep;
            parts.emplace_back(body.substr(pos, end - pos));
            pos = (sep == std::string_view::npos) ? body.size() : sep + 3;
        }
        if (parts.empty()) {
            continue;
        }

        auto pop_target = [](std::string_view ins) -> std::optional<std::string_view> {
            constexpr std::string_view kPrefix = "pop ";
            if (!ins.starts_with(kPrefix) || ins.size() == kPrefix.size()) {
                return std::nullopt;
            }
            return ins.substr(kPrefix.size());
        };

        const auto first = pop_target(parts.front());
        if (!first || *first != target_reg) {
            continue;
        }
        bool ok = true;
        for (std::size_t i = 1; i < parts.size(); ++i) {
            const auto reg = pop_target(parts[i]);
            if (!reg) {
                ok = false;
                break;
            }
            for (auto bad : forbidden) {
                if (*reg == bad) {
                    ok = false;
                    break;
                }
            }
            if (!ok) {
                break;
            }
        }
        if (!ok) {
            continue;
        }
        const std::size_t padding = parts.size() - 1;
        if (!best || padding < best->padding || (padding == best->padding && g.text == exact)) {
            best = FuzzyPop{g, padding};
            if (padding == 0 && g.text == exact) {
                return best; // can't do better than exact
            }
        }
    }
    return best;
}

} // namespace

void RopCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary providing gadgets")->required();
    app.add_option("--syscall", syscall_number, "Build a syscall chain with this number");
    app.add_option("--syscall-arg",
                   syscall_args,
                   "Repeat per arg: --syscall 59 --syscall-arg 0x600000 --syscall-arg 0 ...");
    // --ret2win, --leak, --srop, --format pwntools were advertised
    // in --help with "(currently unsupported)" disclaimers per
    // QA round 1 MAJOR; they parsed flags the binary never
    // implemented. Removed from the CLI surface entirely; the
    // dedicated `srop` subcommand covers SROP; ret2win is a
    // trivial rop with one address that callers can stage from
    // `syms`. They return in v0.2 if the demand materializes.
}

core::Result<core::CommandResult> RopCommand::run(const core::Context& ctx) {
    if (syscall_number < 0) {
        return core::err(core::ErrorCode::UsageError,
                         "rop: pick a strategy (--syscall N --syscall-arg ARG ...)");
    }

    auto loaded = formats::load(target, formats::LoadOptions{ctx.limits.max_file_bytes, true});
    if (!loaded) {
        return core::err(loaded.error());
    }
    const auto a = arch::arch_from_string(loaded->info().arch);
    if (!a || (*a != arch::Arch::X86_64)) {
        return core::err(core::ErrorCode::Unsupported,
                         "rop: only x86_64 --syscall is implemented in this milestone");
    }

    auto sections = collect_executable_sections(*loaded);
    if (sections.empty()) {
        return core::err(core::ErrorCode::NotFound, "rop: no executable sections in target");
    }

    rop::GadgetSearchOptions opts;
    opts.arch = arch::Arch::X86_64;
    opts.terminator = rop::Terminator::Ret;
    opts.max_depth = 4;
    auto gadgets = rop::find_gadgets(sections, opts);
    if (!gadgets) {
        return core::err(gadgets.error());
    }

    // Build the forbidden-register set: any register we're about to
    // populate with another pop gadget can't be clobbered by an
    // intermediate pop in a fuzzy match for a different register.
    std::vector<std::string_view> forbidden;
    forbidden.emplace_back("rax");
    if (!syscall_args.empty())
        forbidden.emplace_back("rdi");
    if (syscall_args.size() >= 2)
        forbidden.emplace_back("rsi");
    if (syscall_args.size() >= 3)
        forbidden.emplace_back("rdx");

    auto find_for = [&](std::string_view reg) {
        std::vector<std::string_view> local(forbidden.begin(), forbidden.end());
        local.erase(std::remove(local.begin(), local.end(), reg), local.end());
        return find_pop_gadget(*gadgets, reg, local);
    };

    auto pop_rax = find_for("rax");
    auto pop_rdi = find_for("rdi");
    auto pop_rsi = find_for("rsi");
    auto pop_rdx = find_for("rdx");
    auto syscall_g = find_gadget_text_eq(*gadgets, "syscall");
    if (!syscall_g)
        syscall_g = find_gadget_text_eq(*gadgets, "syscall ; ret");

    std::vector<std::string> missing;
    if (!pop_rax)
        missing.emplace_back("pop rax ; ... ; ret");
    if (!syscall_g)
        missing.emplace_back("syscall");
    if (!pop_rdi && !syscall_args.empty())
        missing.emplace_back("pop rdi ; ... ; ret");
    if (!pop_rsi && syscall_args.size() >= 2)
        missing.emplace_back("pop rsi ; ... ; ret");
    if (!pop_rdx && syscall_args.size() >= 3)
        missing.emplace_back("pop rdx ; ... ; ret");
    if (!missing.empty()) {
        std::string m;
        for (std::size_t i = 0; i < missing.size(); ++i) {
            if (i != 0)
                m += ", ";
            m += missing[i];
        }
        return core::err(core::ErrorCode::NotFound,
                         "rop: cannot build syscall chain, missing gadgets: " + m);
    }

    auto fmt_hex = [](std::uint64_t v) {
        char b[32];
        std::snprintf(b, sizeof b, "0x%lx", (unsigned long) v);
        return std::string(b);
    };

    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "ROP chain (x86_64 syscall " + std::to_string(syscall_number) + ")";

    auto add_pop = [&](const FuzzyPop& fp, std::uint64_t value) {
        core::Finding addr_f;
        addr_f.title = fp.gadget.text;
        addr_f.detail = fmt_hex(fp.gadget.address) + "   value=" + fmt_hex(value);
        sec.findings.push_back(std::move(addr_f));
        // Each intermediate pop consumes one stack slot. Surface those
        // slots explicitly so the operator knows the chain needs
        // padding bytes between this gadget's value and the next
        // gadget address.
        for (std::size_t i = 0; i < fp.padding; ++i) {
            core::Finding pad_f;
            pad_f.title = "  (padding slot " + std::to_string(i + 1) + ")";
            pad_f.detail = "0x0000000000000000";
            sec.findings.push_back(std::move(pad_f));
        }
    };

    add_pop(*pop_rax, static_cast<std::uint64_t>(syscall_number));
    if (!syscall_args.empty())
        add_pop(*pop_rdi, syscall_args[0]);
    if (syscall_args.size() >= 2)
        add_pop(*pop_rsi, syscall_args[1]);
    if (syscall_args.size() >= 3)
        add_pop(*pop_rdx, syscall_args[2]);
    {
        core::Finding syscall_f;
        syscall_f.title = syscall_g->text;
        syscall_f.detail = fmt_hex(syscall_g->address);
        sec.findings.push_back(std::move(syscall_f));
    }

    res.summary = "chain has " + std::to_string(sec.findings.size()) + " items";
    return res;
}

} // namespace abcpwn::commands
