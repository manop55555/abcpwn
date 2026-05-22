// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/rop.hpp"

#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
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

} // namespace

void RopCommand::setup(CLI::App& app) {
    app.add_option("target", target, "Binary providing gadgets")->required();
    app.add_option("--syscall", syscall_number, "Build a syscall chain with this number");
    app.add_option("--syscall-arg",
                   syscall_args,
                   "Repeat per arg: --syscall 59 --syscall-arg 0x600000 --syscall-arg 0 ...");
    app.add_option("--ret2win", ret2win, "Symbol name to jump to (currently unsupported)");
    app.add_option("--leak", leak_symbol, "Symbol whose address to leak (currently unsupported)");
    app.add_flag("--srop", srop, "Use sigreturn-oriented programming (currently unsupported)");
    app.add_option("--format", format, "pretty | pwntools (pretty implemented)");
}

core::Result<core::CommandResult> RopCommand::run(const core::Context& /*ctx*/) {
    if (syscall_number < 0 && ret2win.empty() && leak_symbol.empty() && !srop) {
        return core::err(core::ErrorCode::UsageError,
                         "rop: pick a strategy (--syscall N, --ret2win SYM, --leak SYM, --srop)");
    }
    if (syscall_number < 0) {
        return core::err(core::ErrorCode::Unsupported,
                         "rop: only --syscall N is implemented in this milestone; "
                         "--ret2win, --leak, and --srop land in subsequent versions");
    }

    auto loaded = formats::load(target);
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

    auto pop_rax = find_gadget_text_eq(*gadgets, "pop rax ; ret");
    auto pop_rdi = find_gadget_text_eq(*gadgets, "pop rdi ; ret");
    auto pop_rsi = find_gadget_text_eq(*gadgets, "pop rsi ; ret");
    auto pop_rdx = find_gadget_text_eq(*gadgets, "pop rdx ; ret");
    auto syscall_g = find_gadget_text_eq(*gadgets, "syscall");
    if (!syscall_g)
        syscall_g = find_gadget_text_eq(*gadgets, "syscall ; ret");

    std::vector<std::string> missing;
    if (!pop_rax)
        missing.emplace_back("pop rax ; ret");
    if (!syscall_g)
        missing.emplace_back("syscall");
    if (!pop_rdi && !syscall_args.empty())
        missing.emplace_back("pop rdi ; ret");
    if (!pop_rsi && syscall_args.size() >= 2)
        missing.emplace_back("pop rsi ; ret");
    if (!pop_rdx && syscall_args.size() >= 3)
        missing.emplace_back("pop rdx ; ret");
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

    auto add_pair = [&](std::string_view what,
                        std::uint64_t addr,
                        std::optional<std::uint64_t> val = std::nullopt) {
        core::Finding f;
        f.title = std::string(what);
        f.detail = fmt_hex(addr);
        if (val) {
            f.detail += "   value=" + fmt_hex(*val);
        }
        sec.findings.push_back(std::move(f));
    };

    add_pair("pop rax ; ret", pop_rax->address, static_cast<std::uint64_t>(syscall_number));
    if (!syscall_args.empty())
        add_pair("pop rdi ; ret", pop_rdi->address, syscall_args[0]);
    if (syscall_args.size() >= 2)
        add_pair("pop rsi ; ret", pop_rsi->address, syscall_args[1]);
    if (syscall_args.size() >= 3)
        add_pair("pop rdx ; ret", pop_rdx->address, syscall_args[2]);
    add_pair("syscall", syscall_g->address);

    res.summary = "chain has " + std::to_string(sec.findings.size()) + " items";
    return res;
}

} // namespace abcpwn::commands
