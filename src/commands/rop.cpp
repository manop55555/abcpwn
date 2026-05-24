// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/rop.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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

// Parse a gadget whose body is purely `pop <reg>` instructions ending in
// `ret` (e.g. "pop rdi ; pop rsi ; ret", or bare "ret"). Returns the
// ordered list of popped registers, or nullopt if the gadget contains
// anything else. These are the only gadgets safe to chain blindly: every
// stack slot maps to exactly one register pop with no side effects, so a
// single `pop rdi ; pop rsi ; pop rdx ; ret` can set three argument
// registers at once.
[[nodiscard]] std::optional<std::vector<std::string>> parse_pop_chain(std::string_view text) {
    if (text != "ret" && !text.ends_with(" ; ret")) {
        return std::nullopt;
    }
    std::vector<std::string> regs;
    if (text == "ret") {
        return regs; // no pops
    }
    std::string_view body = text;
    body.remove_suffix(6); // strip " ; ret"
    std::size_t pos = 0;
    while (true) {
        const auto sep = body.find(" ; ", pos);
        const auto end = (sep == std::string_view::npos) ? body.size() : sep;
        const std::string_view part = body.substr(pos, end - pos);
        constexpr std::string_view kPrefix = "pop ";
        if (!part.starts_with(kPrefix) || part.size() == kPrefix.size()) {
            return std::nullopt; // not a pure pop chain
        }
        regs.emplace_back(part.substr(kPrefix.size()));
        if (sep == std::string_view::npos) {
            break;
        }
        pos = sep + 3;
    }
    return regs;
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
    opts.max_depth = 6; // up to 5 pops + ret, so one gadget can set many args
    auto gadgets = rop::find_gadgets(sections, opts);
    if (!gadgets) {
        return core::err(gadgets.error());
    }

    // x86_64 syscall ABI: number in rax; arguments in rdi, rsi, rdx,
    // r10, r8, r9 (r10, not rcx -- the syscall instruction clobbers rcx).
    static constexpr std::array<std::string_view, 6> kArgRegs = {
        {"rdi", "rsi", "rdx", "r10", "r8", "r9"}};
    if (syscall_args.size() > kArgRegs.size()) {
        return core::err(core::ErrorCode::UsageError,
                         "rop: x86_64 syscalls take at most 6 arguments");
    }

    // Registers to set, in priority order, each with its value.
    std::vector<std::pair<std::string, std::uint64_t>> needed;
    needed.emplace_back("rax", static_cast<std::uint64_t>(syscall_number));
    for (std::size_t i = 0; i < syscall_args.size(); ++i) {
        needed.emplace_back(std::string(kArgRegs[i]), syscall_args[i]);
    }

    // Catalogue every pure pop-chain gadget with its ordered pop list. A
    // single gadget can populate several argument registers at once
    // (e.g. pop rdi ; pop rsi ; pop rdx ; ret), so the chain is built by
    // covering the needed set with a COMBINATION of these gadgets rather
    // than demanding a dedicated `pop <reg> ; ret` per register.
    struct PopGadget {
        rop::Gadget gadget;
        std::vector<std::string> regs;
    };
    std::vector<PopGadget> catalog;
    for (const auto& g : *gadgets) {
        auto regs = parse_pop_chain(g.text);
        if (regs && !regs->empty()) {
            catalog.push_back({g, std::move(*regs)});
        }
    }
    std::sort(catalog.begin(), catalog.end(), [](const PopGadget& x, const PopGadget& y) {
        return x.gadget.address < y.gadget.address;
    });

    // A syscall gadget terminates the chain. The pop search above is
    // ret-terminated, so it only sees `syscall ; ret`; run a second
    // syscall-terminated search so a bare `syscall` (the common case for
    // a final execve, where nothing needs to run afterwards) is found.
    std::optional<rop::Gadget> syscall_g = find_gadget_text_eq(*gadgets, "syscall ; ret");
    if (!syscall_g) {
        rop::GadgetSearchOptions sysopts;
        sysopts.arch = arch::Arch::X86_64;
        sysopts.terminator = rop::Terminator::Syscall;
        sysopts.max_depth = 2;
        if (auto sg = rop::find_gadgets(sections, sysopts)) {
            syscall_g = find_gadget_text_eq(*sg, "syscall");
        }
    }

    // Greedy set cover over the needed registers.
    std::vector<std::string> reg_names;
    reg_names.reserve(needed.size());
    for (const auto& nv : needed) {
        reg_names.push_back(nv.first);
    }
    std::vector<bool> covered(reg_names.size(), false);
    auto count_new = [&](const PopGadget& pg) {
        std::size_t c = 0;
        for (std::size_t i = 0; i < reg_names.size(); ++i) {
            if (!covered[i]
                && std::find(pg.regs.begin(), pg.regs.end(), reg_names[i]) != pg.regs.end()) {
                ++c;
            }
        }
        return c;
    };
    std::vector<const PopGadget*> chosen;
    while (true) {
        const PopGadget* best = nullptr;
        std::size_t best_new = 0;
        for (const auto& pg : catalog) {
            const std::size_t nw = count_new(pg);
            if (nw == 0) {
                continue;
            }
            // Most newly-covered wins; tie-break to fewest pops (least
            // padding), then lowest address (catalog is address-sorted,
            // so the first equal candidate is kept).
            if (best == nullptr || nw > best_new
                || (nw == best_new && pg.regs.size() < best->regs.size())) {
                best = &pg;
                best_new = nw;
            }
        }
        if (best == nullptr) {
            break;
        }
        chosen.push_back(best);
        for (std::size_t i = 0; i < reg_names.size(); ++i) {
            if (!covered[i]
                && std::find(best->regs.begin(), best->regs.end(), reg_names[i])
                       != best->regs.end()) {
                covered[i] = true;
            }
        }
    }

    std::vector<std::string> missing;
    for (std::size_t i = 0; i < reg_names.size(); ++i) {
        if (!covered[i]) {
            missing.push_back("pop " + reg_names[i]);
        }
    }
    if (!syscall_g) {
        missing.emplace_back("syscall");
    }
    if (!missing.empty()) {
        std::string m;
        for (std::size_t i = 0; i < missing.size(); ++i) {
            if (i != 0) {
                m += ", ";
            }
            m += missing[i];
        }
        // The args parsed fine; the target simply lacks the gadgets to
        // build this chain. NotFound (7) means "path does not exist", so
        // route to Unsupported (10) -- consistent with gadget's
        // no-exec-sections case (DEF-1 / DEF-19, cross-tier note from #41).
        return core::err(core::ErrorCode::Unsupported,
                         "rop: cannot build syscall chain, missing gadgets: " + m);
    }

    auto fmt_hex = [](std::uint64_t v) {
        char b[32];
        std::snprintf(b, sizeof b, "0x%lx", (unsigned long) v);
        return std::string(b);
    };

    std::map<std::string, std::uint64_t> value_of;
    for (const auto& nv : needed) {
        value_of[nv.first] = nv.second;
    }

    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "ROP chain (x86_64 syscall " + std::to_string(syscall_number) + ")";

    // Emit each chosen gadget followed by the stack slots its pops
    // consume: a needed register gets its value (idempotent if popped by
    // more than one chosen gadget), a don't-care pop gets a padding slot.
    for (const auto* pg : chosen) {
        core::Finding gf;
        gf.title = pg->gadget.text;
        gf.detail = fmt_hex(pg->gadget.address);
        sec.findings.push_back(std::move(gf));
        for (const auto& reg : pg->regs) {
            core::Finding slot;
            const auto it = value_of.find(reg);
            if (it != value_of.end()) {
                slot.title = "  -> " + reg;
                slot.detail = fmt_hex(it->second);
            } else {
                slot.title = "  (padding: clobbers " + reg + ")";
                slot.detail = "0x0000000000000000";
            }
            sec.findings.push_back(std::move(slot));
        }
    }
    {
        core::Finding syscall_f;
        syscall_f.title = syscall_g->text;
        syscall_f.detail = fmt_hex(syscall_g->address);
        sec.findings.push_back(std::move(syscall_f));
    }

    res.summary = "chain: " + std::to_string(chosen.size()) + " gadget(s), "
                  + std::to_string(sec.findings.size()) + " stack items";
    return res;
}

} // namespace abcpwn::commands
