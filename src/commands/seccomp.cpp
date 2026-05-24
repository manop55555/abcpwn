// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/seccomp.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>
#include <LIEF/LIEF.hpp>

#include "abcpwn/arch/syscalls.hpp"
#include "abcpwn/commands/encoding.hpp"
#include "abcpwn/core/safe_io.hpp"
#include "abcpwn/formats/binary_loader.hpp"

namespace abcpwn::commands::seccomp {

namespace {

// cBPF instruction classes (low 3 bits of `code`).
constexpr std::uint16_t kBpfLd = 0x00;
constexpr std::uint16_t kBpfLdx = 0x01;
constexpr std::uint16_t kBpfSt = 0x02;
constexpr std::uint16_t kBpfStx = 0x03;
constexpr std::uint16_t kBpfAlu = 0x04;
constexpr std::uint16_t kBpfJmp = 0x05;
constexpr std::uint16_t kBpfRet = 0x06;
constexpr std::uint16_t kBpfMisc = 0x07;

// Size modifiers (bits 3-4).
constexpr std::uint16_t kBpfW = 0x00;
constexpr std::uint16_t kBpfH = 0x08;
constexpr std::uint16_t kBpfB = 0x10;

// Addressing modes (bits 5-7).
constexpr std::uint16_t kBpfAbs = 0x20;
constexpr std::uint16_t kBpfInd = 0x40;
constexpr std::uint16_t kBpfImm = 0x00;
constexpr std::uint16_t kBpfMem = 0x60;
constexpr std::uint16_t kBpfLen = 0x80;

// ALU ops (bits 4-7 of `code`).
constexpr std::uint16_t kBpfAdd = 0x00;
constexpr std::uint16_t kBpfSub = 0x10;
constexpr std::uint16_t kBpfMul = 0x20;
constexpr std::uint16_t kBpfDiv = 0x30;
constexpr std::uint16_t kBpfOr = 0x40;
constexpr std::uint16_t kBpfAnd = 0x50;
constexpr std::uint16_t kBpfLsh = 0x60;
constexpr std::uint16_t kBpfRsh = 0x70;
constexpr std::uint16_t kBpfNeg = 0x80;
constexpr std::uint16_t kBpfXor = 0xa0;

// Conditional jumps (bits 4-7 of `code` when class == JMP).
constexpr std::uint16_t kBpfJa = 0x00;
constexpr std::uint16_t kBpfJeq = 0x10;
constexpr std::uint16_t kBpfJgt = 0x20;
constexpr std::uint16_t kBpfJge = 0x30;
constexpr std::uint16_t kBpfJset = 0x40;

// SECCOMP_RET_* action codes.
constexpr std::uint32_t kSeccompRetKill = 0x00000000;
constexpr std::uint32_t kSeccompRetTrap = 0x00030000;
constexpr std::uint32_t kSeccompRetErrno = 0x00050000;
constexpr std::uint32_t kSeccompRetTrace = 0x7ff00000;
constexpr std::uint32_t kSeccompRetAllow = 0x7fff0000;
constexpr std::uint32_t kSeccompRetLog = 0x7ffc0000;

[[nodiscard]] std::string action_name(std::uint32_t k) {
    const std::uint32_t a = k & 0xffff0000U;
    switch (a) {
    case kSeccompRetKill:
        return "KILL";
    case kSeccompRetTrap:
        return "TRAP";
    case kSeccompRetErrno:
        return "ERRNO(" + std::to_string(k & 0xffffU) + ")";
    case kSeccompRetTrace:
        return "TRACE";
    case kSeccompRetAllow:
        return "ALLOW";
    case kSeccompRetLog:
        return "LOG";
    default: {
        char buf[24];
        std::snprintf(buf, sizeof buf, "0x%08x", k);
        return std::string(buf);
    }
    }
}

[[nodiscard]] std::string alu_mnemonic(std::uint16_t op) {
    switch (op) {
    case kBpfAdd:
        return "+=";
    case kBpfSub:
        return "-=";
    case kBpfMul:
        return "*=";
    case kBpfDiv:
        return "/=";
    case kBpfOr:
        return "|=";
    case kBpfAnd:
        return "&=";
    case kBpfLsh:
        return "<<=";
    case kBpfRsh:
        return ">>=";
    case kBpfXor:
        return "^=";
    default:
        return "??";
    }
}

// --- static seccomp filter detection (the `dump` action) ----------------
//
// abcpwn never executes the target, so `dump` finds the filter by static
// analysis: most CTF (and libseccomp-free) binaries embed the compiled
// BPF as a `struct sock_filter[]` in a data section. We anchor a byte
// search on the conventional first instruction and validate candidates
// at the program level.

// A plausible classic-BPF opcode? seccomp uses a small subset; we stay
// lenient per-instruction and let the program-level validator
// (reachability + ends-in-RET) reject coincidental matches.
[[nodiscard]] bool valid_bpf_code(std::uint16_t code) {
    const std::uint16_t cls = code & 0x07;
    switch (cls) {
    case kBpfLd:
    case kBpfLdx: {
        const std::uint16_t mode = code & 0xe0;
        return mode == kBpfImm || mode == kBpfAbs || mode == kBpfInd || mode == kBpfMem
               || mode == kBpfLen;
    }
    case kBpfSt:
    case kBpfStx:
        return (code & 0xf8) == 0; // cBPF stores carry no size/mode bits
    case kBpfAlu: {
        const std::uint16_t op = code & 0xf0;
        return op == kBpfAdd || op == kBpfSub || op == kBpfMul || op == kBpfDiv || op == kBpfOr
               || op == kBpfAnd || op == kBpfLsh || op == kBpfRsh || op == kBpfNeg || op == kBpfXor
               || op == 0x90; // MOD
    }
    case kBpfJmp: {
        const std::uint16_t op = code & 0xf0;
        return op == kBpfJa || op == kBpfJeq || op == kBpfJgt || op == kBpfJge || op == kBpfJset;
    }
    case kBpfRet:
        return code == 0x06 || code == 0x16; // RET|K or RET|A
    case kBpfMisc:
        return code == 0x07 || code == 0x87; // TAX / TXA
    default:
        return false;
    }
}

// Parse consecutive 8-byte sock_filter entries from `off`, then walk
// control flow from instruction 0. Returns the reachable program extent
// (instruction count) only if every path stays in range and terminates
// in RET; 0 otherwise. This trims any junk consumed past the real
// program and rejects coincidental opcode runs.
[[nodiscard]] std::size_t bpf_program_extent(std::span<const std::uint8_t> blob, std::size_t off) {
    std::vector<BpfInsn> insns;
    for (std::size_t p = off; p + 8 <= blob.size(); p += 8) {
        const auto code = static_cast<std::uint16_t>(blob[p] | (blob[p + 1] << 8));
        if (!valid_bpf_code(code)) {
            break;
        }
        BpfInsn ins;
        ins.code = code;
        ins.jt = blob[p + 2];
        ins.jf = blob[p + 3];
        ins.k = static_cast<std::uint32_t>(blob[p + 4])
                | (static_cast<std::uint32_t>(blob[p + 5]) << 8)
                | (static_cast<std::uint32_t>(blob[p + 6]) << 16)
                | (static_cast<std::uint32_t>(blob[p + 7]) << 24);
        insns.push_back(ins);
        if (insns.size() >= 4096) {
            break;
        }
    }
    const std::size_t n = insns.size();
    if (n == 0) {
        return 0;
    }
    std::vector<bool> seen(n, false);
    std::vector<std::size_t> work{0};
    std::size_t max_idx = 0;
    bool saw_ret = false;
    auto push = [&](std::size_t target) -> bool {
        if (target >= n) {
            return false; // escapes the candidate range -> not self-contained
        }
        work.push_back(target);
        return true;
    };
    while (!work.empty()) {
        const std::size_t i = work.back();
        work.pop_back();
        if (seen[i]) {
            continue;
        }
        seen[i] = true;
        max_idx = std::max(max_idx, i);
        const auto& ins = insns[i];
        const std::uint16_t cls = ins.code & 0x07;
        if (cls == kBpfRet) {
            saw_ret = true;
            continue;
        }
        if (cls == kBpfJmp) {
            const std::uint16_t op = ins.code & 0xf0;
            if (op == kBpfJa) {
                if (!push(i + 1 + ins.k)) {
                    return 0;
                }
            } else if (!push(i + 1 + ins.jt) || !push(i + 1 + ins.jf)) {
                return 0;
            }
        } else if (!push(i + 1)) {
            return 0; // fell off the end without RET
        }
    }
    return saw_ret ? max_idx + 1 : 0;
}

struct FilterHit {
    std::string section;
    std::uint64_t vaddr{};
    std::vector<std::uint8_t> bytes;
    std::size_t insn_count{};
};

// Scan allocated, non-executable sections for the longest valid static
// BPF program. The anchors (load arch / load nr) only narrow the search;
// bpf_program_extent is the real filter.
[[nodiscard]] std::optional<FilterHit> find_seccomp_filter(const LIEF::ELF::Binary& elf) {
    static constexpr std::array<std::array<std::uint8_t, 8>, 2> anchors = {{
        {{0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}}, // A = arch
        {{0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}, // A = sys_number
    }};
    const auto exec = static_cast<std::uint64_t>(LIEF::ELF::Section::FLAGS::EXECINSTR);
    const auto alloc = static_cast<std::uint64_t>(LIEF::ELF::Section::FLAGS::ALLOC);
    FilterHit best;
    for (const auto& sec : elf.sections()) {
        const auto flags = static_cast<std::uint64_t>(sec.flags());
        if ((flags & alloc) == 0 || (flags & exec) != 0) {
            continue; // data sections only
        }
        const auto raw = sec.content();
        std::vector<std::uint8_t> data(raw.begin(), raw.end());
        if (data.size() < 24) {
            continue;
        }
        std::span<const std::uint8_t> blob(data);
        for (std::size_t off = 0; off + 8 <= blob.size(); ++off) {
            const bool anchored = std::any_of(anchors.begin(), anchors.end(), [&](const auto& anc) {
                return std::equal(anc.begin(), anc.end(), blob.begin() + off);
            });
            if (!anchored) {
                continue;
            }
            const std::size_t extent = bpf_program_extent(blob, off);
            if (extent >= 2 && extent > best.insn_count) {
                best.section = sec.name();
                best.vaddr = sec.virtual_address() + off;
                best.bytes.assign(blob.begin() + off, blob.begin() + off + extent * 8);
                best.insn_count = extent;
            }
        }
    }
    if (best.insn_count == 0) {
        return std::nullopt;
    }
    return best;
}

} // namespace

core::Result<std::vector<BpfInsn>> decode_bpf(std::span<const std::uint8_t> bytes) {
    if (bytes.size() % 8 != 0) {
        return core::err(core::ErrorCode::InvalidInput,
                         "seccomp: BPF buffer must be a multiple of 8 bytes");
    }
    std::vector<BpfInsn> out;
    out.reserve(bytes.size() / 8);
    for (std::size_t i = 0; i < bytes.size(); i += 8) {
        BpfInsn ins;
        ins.code = static_cast<std::uint16_t>(bytes[i] | (bytes[i + 1] << 8));
        ins.jt = bytes[i + 2];
        ins.jf = bytes[i + 3];
        ins.k = static_cast<std::uint32_t>(bytes[i + 4])
                | (static_cast<std::uint32_t>(bytes[i + 5]) << 8)
                | (static_cast<std::uint32_t>(bytes[i + 6]) << 16)
                | (static_cast<std::uint32_t>(bytes[i + 7]) << 24);
        out.push_back(ins);
    }
    return out;
}

std::vector<std::string> disassemble_bpf(std::span<const BpfInsn> insns,
                                         arch::Arch arch_for_syscalls) {
    std::vector<std::string> out;
    out.reserve(insns.size());
    for (std::size_t i = 0; i < insns.size(); ++i) {
        const auto& ins = insns[i];
        char prefix[8];
        std::snprintf(prefix, sizeof prefix, "%3zu: ", i);
        std::string line(prefix);

        const std::uint16_t cls = ins.code & 0x07;
        if (cls == kBpfLd && (ins.code & 0x60) == kBpfAbs) {
            // A = data[k]  -- in seccomp_data the layout is:
            //   0: nr (syscall number)
            //   4: arch
            //   8: instruction pointer
            //   ... (16: args[0..5])
            char buf[64];
            const char* what = "data";
            if (ins.k == 0)
                what = "sys_number";
            else if (ins.k == 4)
                what = "arch";
            else if (ins.k == 8)
                what = "ip_lo";
            else if (ins.k == 12)
                what = "ip_hi";
            std::snprintf(buf, sizeof buf, "A = %s", what);
            line.append(buf);
        } else if (cls == kBpfRet) {
            line.append("return ");
            line.append(action_name(ins.k));
        } else if (cls == kBpfJmp) {
            const std::uint16_t op = ins.code & 0xf0;
            char buf[96];
            if (op == kBpfJa) {
                std::snprintf(buf, sizeof buf, "goto %zu", i + 1 + ins.k);
            } else {
                const char* cmp = "??";
                if (op == kBpfJeq)
                    cmp = "==";
                else if (op == kBpfJgt)
                    cmp = ">";
                else if (op == kBpfJge)
                    cmp = ">=";
                else if (op == kBpfJset)
                    cmp = "&";
                std::snprintf(buf,
                              sizeof buf,
                              "if (A %s 0x%x) goto %zu else goto %zu",
                              cmp,
                              ins.k,
                              i + 1 + ins.jt,
                              i + 1 + ins.jf);
            }
            line.append(buf);
            // Annotate with syscall name when comparing A == k against
            // a known number on the current arch.
            if ((ins.code & 0xf0) == kBpfJeq) {
                if (auto n = arch::syscalls::by_number(arch_for_syscalls,
                                                       static_cast<std::int32_t>(ins.k))) {
                    line.append("  // SYS_");
                    line.append(*n);
                }
            }
        } else if (cls == kBpfAlu) {
            const std::uint16_t op = ins.code & 0xf0;
            char buf[64];
            std::snprintf(buf, sizeof buf, "A %s 0x%x", alu_mnemonic(op).c_str(), ins.k);
            line.append(buf);
        } else {
            char buf[64];
            std::snprintf(buf, sizeof buf, "<unhandled code=0x%04x k=0x%08x>", ins.code, ins.k);
            line.append(buf);
        }
        out.push_back(std::move(line));
    }
    return out;
}

void SeccompCommand::setup(CLI::App& app) {
    app.add_option("action", action, "disasm | dump")->required();
    app.add_option("input", input, "Hex BPF bytes for disasm; binary path for dump");
    app.add_option("--arch", arch_str, "Arch for syscall-name annotations (x86_64 default)");
}

core::Result<core::CommandResult> SeccompCommand::run(const core::Context& ctx) {
    const auto a = arch::arch_from_string(arch_str);
    if (!a) {
        return core::err(core::ErrorCode::UsageError, "seccomp: unknown --arch '" + arch_str + "'");
    }

    if (action == "disasm") {
        auto bytes = encoding::hex_decode(input);
        if (!bytes) {
            return core::err(bytes.error());
        }
        auto decoded = decode_bpf(*bytes);
        if (!decoded) {
            return core::err(decoded.error());
        }
        const auto lines = disassemble_bpf(*decoded, *a);
        core::CommandResult res;
        res.raw_lines = std::move(const_cast<std::vector<std::string>&>(lines));
        res.summary = std::to_string(decoded->size()) + " BPF instructions";
        return res;
    }
    if (action == "dump") {
        auto loaded = formats::load(input, formats::LoadOptions{ctx.limits.max_file_bytes, true});
        if (!loaded) {
            return core::err(loaded.error());
        }
        const auto* elf = dynamic_cast<const LIEF::ELF::Binary*>(loaded->binary());
        if (elf == nullptr) {
            return core::err(
                core::ErrorCode::Unsupported,
                "seccomp dump: target is not ELF; seccomp filters are a Linux concept");
        }
        auto hit = find_seccomp_filter(*elf);
        if (!hit) {
            return core::err(core::ErrorCode::Unsupported,
                             "seccomp dump: no static BPF filter found. The filter may be built "
                             "at runtime (e.g. via libseccomp); capture it with "
                             "`strace -f -e trace=prctl,seccomp <target>` or seccomp-tools, then "
                             "run `abcpwn seccomp disasm <hex>`.");
        }
        auto decoded = decode_bpf(hit->bytes);
        if (!decoded) {
            return core::err(decoded.error());
        }
        core::CommandResult res;
        res.raw_lines = disassemble_bpf(*decoded, *a);
        char summary[176];
        std::snprintf(summary,
                      sizeof summary,
                      "%zu BPF instructions (found in %s at 0x%llx)",
                      hit->insn_count,
                      hit->section.c_str(),
                      static_cast<unsigned long long>(hit->vaddr));
        res.summary = summary;
        return res;
    }
    return core::err(core::ErrorCode::UsageError,
                     "seccomp: unknown action '" + action + "' (supported: disasm | dump)");
}

} // namespace abcpwn::commands::seccomp
