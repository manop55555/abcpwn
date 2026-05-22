// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/rop_search.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <regex>
#include <span>
#include <string>
#include <vector>

#include "abcpwn/arch/disasm.hpp"
#include "abcpwn/core/signal.hpp"

namespace abcpwn::commands::rop {

namespace {

// x86 / x86_64 terminator opcode probe. Multi-byte terminators (e.g.,
// syscall = 0f 05, jmp rax = ff e0) are detected later by the
// disassembler; this byte list is just a cheap pre-filter to know
// where to look back.
[[nodiscard]] bool is_terminator_first_byte(std::uint8_t b, Terminator t, arch::Arch a) noexcept {
    if (a != arch::Arch::X86 && a != arch::Arch::X86_64) {
        return true; // outside x86, scan every offset; slower but correct
    }
    switch (t) {
    case Terminator::Ret:
        return b == 0xc3 || b == 0xc2 || b == 0xcb || b == 0xca;
    case Terminator::Jmp:
        return b == 0xe9 || b == 0xeb || b == 0xff;
    case Terminator::Call:
        return b == 0xe8 || b == 0xff;
    case Terminator::Syscall:
        return b == 0x0f || b == 0xcd;
    case Terminator::All:
        return b == 0xc3 || b == 0xc2 || b == 0xcb || b == 0xca || b == 0xe9 || b == 0xeb
               || b == 0xff || b == 0xe8 || b == 0x0f || b == 0xcd;
    }
    return false;
}

[[nodiscard]] bool is_terminator_text(std::string_view m, Terminator t) noexcept {
    switch (t) {
    case Terminator::Ret:
        return m == "ret" || m == "retf";
    case Terminator::Jmp:
        return m.starts_with("jmp");
    case Terminator::Call:
        return m.starts_with("call");
    case Terminator::Syscall:
        return m == "syscall" || m == "int";
    case Terminator::All:
        return m == "ret" || m == "retf" || m.starts_with("jmp") || m.starts_with("call")
               || m == "syscall" || m == "int";
    }
    return false;
}

[[nodiscard]] bool contains_bad_byte(std::span<const std::uint8_t> bytes,
                                     std::span<const std::uint8_t> bad) noexcept {
    for (const auto b : bytes) {
        for (const auto bc : bad) {
            if (b == bc)
                return true;
        }
    }
    return false;
}

[[nodiscard]] std::string render_gadget_text(const std::vector<arch::Instruction>& insns) {
    std::string s;
    for (std::size_t i = 0; i < insns.size(); ++i) {
        if (i != 0)
            s.append(" ; ");
        s.append(insns[i].text());
    }
    return s;
}

} // namespace

core::Result<std::vector<Gadget>> find_gadgets(std::span<const ExecutableSection> sections,
                                               const GadgetSearchOptions& opts) {
    if (opts.arch != arch::Arch::X86 && opts.arch != arch::Arch::X86_64) {
        return core::err(core::ErrorCode::Unsupported,
                         "gadget: only x86 / x86_64 finders are implemented in this milestone");
    }
    (void) is_terminator_first_byte; // kept for future selective scans

    std::optional<std::regex> filter_rx;
    if (!opts.text_filter.empty()) {
        try {
            filter_rx.emplace(opts.text_filter);
        } catch (const std::regex_error& e) {
            return core::err(core::ErrorCode::InvalidInput,
                             std::string("gadget: bad --filter regex: ") + e.what());
        }
    }

    // Forward-decode at every byte position. For each start, find the
    // first terminator instruction in the next max_depth+1 decoded
    // instructions; if found, that prefix is a candidate gadget. The
    // dedup map keeps the lowest-VA copy of each unique gadget text;
    // results are sorted by address ascending. Cost is O(N *
    // max_depth) per section -- fine for typical CTF binaries.
    std::map<std::string, Gadget> uniques;

    for (const auto& sec : sections) {
        const auto& bytes = sec.bytes;
        for (std::size_t start = 0; start < bytes.size(); ++start) {
            if ((start & 0xff) == 0) {
                if (core::signal::cancellation_requested()) {
                    return core::err(core::ErrorCode::Cancelled, "gadget: cancelled");
                }
                if (opts.progress != nullptr) {
                    opts.progress->advance(0x100);
                }
            }

            std::span<const std::uint8_t> window(bytes.data() + start, bytes.size() - start);

            arch::DisasmOptions dopts;
            dopts.arch = opts.arch;
            dopts.base_address = sec.virtual_address + start;
            dopts.max_instructions = opts.max_depth + 1;
            auto r = arch::disassemble(window, dopts);
            if (!r || r->empty()) {
                continue;
            }

            // Locate the first terminator. If none of the first
            // max_depth+1 instructions terminates, this start does not
            // produce a gadget under the current options.
            std::size_t term_idx = r->size();
            for (std::size_t i = 0; i < r->size(); ++i) {
                if (is_terminator_text((*r)[i].mnemonic, opts.terminator)) {
                    term_idx = i;
                    break;
                }
            }
            if (term_idx == r->size()) {
                continue;
            }
            if (term_idx + 1 > opts.max_depth) {
                continue;
            }

            const auto& term = (*r)[term_idx];
            const std::size_t term_end =
                static_cast<std::size_t>((term.address + term.bytes.size()) - sec.virtual_address);
            std::vector<std::uint8_t> gadget_bytes(bytes.begin() + start, bytes.begin() + term_end);

            if (!opts.bad_chars.empty() && contains_bad_byte(gadget_bytes, opts.bad_chars)) {
                continue;
            }

            std::vector<arch::Instruction> kept(
                r->begin(), r->begin() + static_cast<std::ptrdiff_t>(term_idx + 1));
            std::string text = render_gadget_text(kept);

            if (filter_rx && !std::regex_search(text, *filter_rx)) {
                continue;
            }

            const std::uint64_t va = sec.virtual_address + start;
            auto it = uniques.find(text);
            if (it == uniques.end()) {
                Gadget g;
                g.address = va;
                g.bytes = std::move(gadget_bytes);
                g.text = text;
                uniques.emplace(std::move(text), std::move(g));
            } else if (va < it->second.address) {
                it->second.address = va;
                it->second.bytes = std::move(gadget_bytes);
            }
            if (uniques.size() >= opts.max_results) {
                break;
            }
        }
    }

    std::vector<Gadget> out;
    out.reserve(uniques.size());
    for (auto& [_, g] : uniques) {
        out.push_back(std::move(g));
    }
    std::sort(out.begin(), out.end(), [](const Gadget& a, const Gadget& b) {
        return a.address < b.address;
    });
    return out;
}

} // namespace abcpwn::commands::rop
