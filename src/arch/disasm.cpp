// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/arch/disasm.hpp"

#include <cstring>
#include <string>
#include <utility>

#include <capstone/capstone.h>

namespace abcpwn::arch {

namespace {

struct CsHandle {
    csh handle{0};
    bool valid{false};

    ~CsHandle() {
        if (valid) {
            cs_close(&handle);
        }
    }
};

struct CsConfig {
    cs_arch arch{CS_ARCH_X86};
    cs_mode mode{CS_MODE_64};
    bool supported{true};
};

CsConfig pick(const DisasmOptions& opts) {
    CsConfig c;
    const auto endian_flag =
        (opts.endian == Endian::Big) ? CS_MODE_BIG_ENDIAN : CS_MODE_LITTLE_ENDIAN;
    switch (opts.arch) {
    case Arch::X86:
        c.arch = CS_ARCH_X86;
        c.mode = static_cast<cs_mode>(CS_MODE_32 | endian_flag);
        break;
    case Arch::X86_64:
        c.arch = CS_ARCH_X86;
        c.mode = static_cast<cs_mode>(CS_MODE_64 | endian_flag);
        break;
    case Arch::Arm:
        c.arch = CS_ARCH_ARM;
        c.mode =
            static_cast<cs_mode>((opts.thumb_mode ? CS_MODE_THUMB : CS_MODE_ARM) | endian_flag);
        break;
    case Arch::Aarch64:
        c.arch = CS_ARCH_ARM64;
        c.mode = static_cast<cs_mode>(CS_MODE_ARM | endian_flag);
        break;
    case Arch::Mips:
        c.arch = CS_ARCH_MIPS;
        c.mode = static_cast<cs_mode>(CS_MODE_MIPS32 | endian_flag);
        break;
    case Arch::Mips64:
        c.arch = CS_ARCH_MIPS;
        c.mode = static_cast<cs_mode>(CS_MODE_MIPS64 | endian_flag);
        break;
    case Arch::Ppc:
        c.arch = CS_ARCH_PPC;
        c.mode = static_cast<cs_mode>(CS_MODE_32 | endian_flag);
        break;
    case Arch::Ppc64:
        c.arch = CS_ARCH_PPC;
        c.mode = static_cast<cs_mode>(CS_MODE_64 | endian_flag);
        break;
    case Arch::Riscv32:
        c.arch = CS_ARCH_RISCV;
        c.mode = static_cast<cs_mode>(CS_MODE_RISCV32 | endian_flag);
        break;
    case Arch::Riscv64:
        c.arch = CS_ARCH_RISCV;
        c.mode = static_cast<cs_mode>(CS_MODE_RISCV64 | endian_flag);
        break;
    case Arch::Unknown:
    default:
        c.supported = false;
        break;
    }
    return c;
}

} // namespace

core::Result<std::vector<Instruction>> disassemble(std::span<const std::uint8_t> bytes,
                                                   const DisasmOptions& opts) {
    const auto cfg = pick(opts);
    if (!cfg.supported) {
        return core::err(core::ErrorCode::Unsupported,
                         "disasm: arch '" + std::string(arch_name(opts.arch)) + "' not supported");
    }

    CsHandle ch;
    if (const cs_err r = cs_open(cfg.arch, cfg.mode, &ch.handle); r != CS_ERR_OK) {
        return core::err(core::ErrorCode::InternalError,
                         std::string("disasm: cs_open failed: ") + cs_strerror(r));
    }
    ch.valid = true;
    cs_option(ch.handle, CS_OPT_DETAIL, CS_OPT_OFF);

    cs_insn* insn = nullptr;
    const std::size_t count = cs_disasm(
        ch.handle, bytes.data(), bytes.size(), opts.base_address, opts.max_instructions, &insn);

    std::vector<Instruction> out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        Instruction ins;
        ins.address = insn[i].address;
        ins.mnemonic = insn[i].mnemonic;
        ins.op_str = insn[i].op_str;
        ins.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
        out.emplace_back(std::move(ins));
    }
    if (insn != nullptr) {
        cs_free(insn, count);
    }
    return out;
}

} // namespace abcpwn::arch
