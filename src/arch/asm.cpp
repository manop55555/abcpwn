// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/arch/asm.hpp"

#include <string>
#include <vector>

namespace abcpwn::arch {

#if defined(ABCPWN_WITH_KEYSTONE) && ABCPWN_WITH_KEYSTONE

#include <keystone/keystone.h>

namespace {

struct KsHandle {
    ks_engine* engine{nullptr};
    ~KsHandle() {
        if (engine != nullptr) {
            ks_close(engine);
        }
    }
};

ks_arch ks_arch_for(Arch a) {
    switch (a) {
    case Arch::X86:
    case Arch::X86_64:
        return KS_ARCH_X86;
    case Arch::Arm:
        return KS_ARCH_ARM;
    case Arch::Aarch64:
        return KS_ARCH_ARM64;
    case Arch::Mips:
    case Arch::Mips64:
        return KS_ARCH_MIPS;
    case Arch::Ppc:
    case Arch::Ppc64:
        return KS_ARCH_PPC;
    case Arch::Riscv32:
    case Arch::Riscv64:
        return KS_ARCH_RISCV;
    default:
        return static_cast<ks_arch>(-1);
    }
}

ks_mode ks_mode_for(const AsmOptions& opts) {
    const ks_mode endian_flag =
        (opts.endian == Endian::Big) ? KS_MODE_BIG_ENDIAN : KS_MODE_LITTLE_ENDIAN;
    switch (opts.arch) {
    case Arch::X86:
        return static_cast<ks_mode>(KS_MODE_32 | endian_flag);
    case Arch::X86_64:
        return static_cast<ks_mode>(KS_MODE_64 | endian_flag);
    case Arch::Arm:
        return static_cast<ks_mode>((opts.thumb_mode ? KS_MODE_THUMB : KS_MODE_ARM) | endian_flag);
    case Arch::Aarch64:
        return static_cast<ks_mode>(endian_flag);
    case Arch::Mips:
        return static_cast<ks_mode>(KS_MODE_MIPS32 | endian_flag);
    case Arch::Mips64:
        return static_cast<ks_mode>(KS_MODE_MIPS64 | endian_flag);
    case Arch::Ppc:
        return static_cast<ks_mode>(KS_MODE_32 | endian_flag);
    case Arch::Ppc64:
        return static_cast<ks_mode>(KS_MODE_64 | endian_flag);
    case Arch::Riscv32:
        return static_cast<ks_mode>(KS_MODE_RISCV32 | endian_flag);
    case Arch::Riscv64:
        return static_cast<ks_mode>(KS_MODE_RISCV64 | endian_flag);
    default:
        return static_cast<ks_mode>(endian_flag);
    }
}

} // namespace

core::Result<std::vector<std::uint8_t>> assemble(std::string_view source, const AsmOptions& opts) {
    const auto k_arch = ks_arch_for(opts.arch);
    if (static_cast<int>(k_arch) < 0) {
        return core::err(core::ErrorCode::Unsupported, "asm: arch not supported");
    }

    KsHandle kh;
    if (ks_open(k_arch, ks_mode_for(opts), &kh.engine) != KS_ERR_OK) {
        return core::err(core::ErrorCode::InternalError, "asm: ks_open failed");
    }

    unsigned char* encode = nullptr;
    size_t enc_size = 0;
    size_t stat_count = 0;
    std::string src(source);
    if (ks_asm(kh.engine, src.c_str(), opts.base_address, &encode, &enc_size, &stat_count)
        != KS_ERR_OK) {
        const ks_err e = ks_errno(kh.engine);
        return core::err(core::ErrorCode::InvalidInput, std::string("asm: ") + ks_strerror(e));
    }

    std::vector<std::uint8_t> out(encode, encode + enc_size);
    ks_free(encode);
    return out;
}

#else // ABCPWN_WITH_KEYSTONE

core::Result<std::vector<std::uint8_t>> assemble(std::string_view /*source*/,
                                                 const AsmOptions& /*opts*/) {
    return core::err(core::ErrorCode::FeatureDisabled,
                     "asm: this build of abcpwn was compiled without Keystone "
                     "(Apache-2.0 variant). Use the abcpwn-full release artifact, "
                     "or rebuild with -DABCPWN_WITH_KEYSTONE=ON to enable.");
}

#endif

} // namespace abcpwn::arch
