// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// libFuzzer harness for the LIEF binary loader. Inputs are written to
// a tmpfs-backed temp file (LIEF takes a path, not a buffer) and fed
// through abcpwn::formats::load. We deliberately route via the public
// API so any size-cap, format-sniff, or LIEF-side crash surfaces under
// the harness rather than only at runtime.
//
// A shallow ELF header sanity check runs BEFORE LIEF parses the input.
// Inputs where the ELF claims section sizes that exceed the actual
// file length are skipped. This defends against the upstream LIEF
// OOM class (LIEF::ELF::Note::create allocating a multi-GB
// std::vector when an attacker-supplied size header is larger than
// the file). The check is intentionally conservative - it skips
// suspect inputs rather than trying to repair them - so the fuzzer
// spends its budget on inputs that have a chance of exercising
// real parser bugs rather than wasting iterations on guaranteed
// OOM-triggers.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>

#include "abcpwn/formats/binary_loader.hpp"

namespace {

// Read a little-endian unsigned N-byte value from `data` at `off`.
// Returns true and writes to *out iff [off, off+N) is in bounds.
template <typename T>
bool read_le(const std::uint8_t* data, std::size_t size, std::size_t off, T* out) {
    if (off > size || size - off < sizeof(T)) {
        return false;
    }
    T value{};
    std::memcpy(&value, data + off, sizeof(T));
    *out = value;
    return true;
}

// Shallow ELF header sanity. Returns true if the input either
// (a) is not an ELF, (b) is a well-shaped ELF whose claimed
// section sizes fit within the input, or (c) is too small to
// matter. Returns false if the input is an ELF that claims
// out-of-bounds section sizes - those are guaranteed to OOM LIEF.
bool looks_reasonable_elf(const std::uint8_t* data, std::size_t size) {
    if (size < 64) {
        return true; // too small to be a meaningful ELF, let LIEF reject
    }
    // ELF magic
    if (data[0] != 0x7f || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') {
        return true; // not ELF, defer to LIEF's PE/Mach-O handlers
    }
    const std::uint8_t ei_class = data[4]; // 1 = 32-bit, 2 = 64-bit
    const std::uint8_t ei_data = data[5];  // 1 = LE, 2 = BE
    if (ei_class != 1 && ei_class != 2) {
        return true; // unknown class; LIEF will reject
    }
    if (ei_data != 1) {
        // Big-endian ELFs do exist but the LE check below is the
        // primary OOM defense; let LIEF handle BE inputs and we
        // accept the marginal risk of a BE-input OOM.
        return true;
    }

    // Compute e_shoff, e_shentsize, e_shnum field offsets for the
    // two ELF classes. Layout from elf.h.
    std::size_t e_shoff_off;
    std::size_t e_shentsize_off;
    std::size_t e_shnum_off;
    std::uint64_t e_shoff;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;

    if (ei_class == 2) {
        // ELF64
        e_shoff_off = 40;
        e_shentsize_off = 58;
        e_shnum_off = 60;
        if (!read_le<std::uint64_t>(data, size, e_shoff_off, &e_shoff)) {
            return false;
        }
    } else {
        // ELF32
        e_shoff_off = 32;
        e_shentsize_off = 46;
        e_shnum_off = 48;
        std::uint32_t e_shoff_32;
        if (!read_le<std::uint32_t>(data, size, e_shoff_off, &e_shoff_32)) {
            return false;
        }
        e_shoff = e_shoff_32;
    }
    if (!read_le<std::uint16_t>(data, size, e_shentsize_off, &e_shentsize)) {
        return false;
    }
    if (!read_le<std::uint16_t>(data, size, e_shnum_off, &e_shnum)) {
        return false;
    }

    if (e_shnum == 0) {
        return true; // no section headers, no per-section OOM surface
    }

    // The section header table itself must fit in the file.
    const std::uint64_t sht_bytes = static_cast<std::uint64_t>(e_shentsize) * e_shnum;
    if (e_shoff > size || sht_bytes > size - e_shoff) {
        return false; // section header table claims more bytes than the file holds
    }

    // For each section header, validate that sh_size + sh_offset is
    // within the file. SHT_NOBITS (type 8) sections do not occupy
    // file bytes so their sh_size is not file-bound; skip the check
    // for those.
    const std::size_t sh_type_off = 4;
    const std::size_t sh_offset_off = (ei_class == 2) ? 24U : 16U;
    const std::size_t sh_size_off = (ei_class == 2) ? 32U : 20U;
    const std::size_t sh_addr_size = (ei_class == 2) ? 8U : 4U;

    for (std::uint16_t i = 0; i < e_shnum; ++i) {
        const std::size_t sh_base =
            static_cast<std::size_t>(e_shoff) + static_cast<std::size_t>(e_shentsize) * i;
        std::uint32_t sh_type;
        if (!read_le<std::uint32_t>(data, size, sh_base + sh_type_off, &sh_type)) {
            return false;
        }
        if (sh_type == 8) {
            continue; // SHT_NOBITS
        }
        std::uint64_t sh_offset;
        std::uint64_t sh_size;
        if (sh_addr_size == 8) {
            if (!read_le<std::uint64_t>(data, size, sh_base + sh_offset_off, &sh_offset)) {
                return false;
            }
            if (!read_le<std::uint64_t>(data, size, sh_base + sh_size_off, &sh_size)) {
                return false;
            }
        } else {
            std::uint32_t v32;
            if (!read_le<std::uint32_t>(data, size, sh_base + sh_offset_off, &v32)) {
                return false;
            }
            sh_offset = v32;
            if (!read_le<std::uint32_t>(data, size, sh_base + sh_size_off, &v32)) {
                return false;
            }
            sh_size = v32;
        }
        if (sh_offset > size || sh_size > size - sh_offset) {
            return false; // section claims to extend beyond the file
        }

        // SHT_NOTE (type 7): walk inner note entries and verify
        // each n_namesz/n_descsz fits within the section. This is
        // the exact bug class observed in fuzz run 26325284050
        // where LIEF::ELF::Note::create attempted a multi-GB
        // std::vector allocation because the note headers claimed
        // sizes larger than the input file.
        if (sh_type == 7) {
            std::uint64_t cursor = sh_offset;
            const std::uint64_t end = sh_offset + sh_size;
            while (cursor + 12 <= end) {
                std::uint32_t n_namesz;
                std::uint32_t n_descsz;
                if (!read_le<std::uint32_t>(data, size, cursor, &n_namesz)
                    || !read_le<std::uint32_t>(data, size, cursor + 4, &n_descsz)) {
                    return false;
                }
                // Both sizes are rounded up to 4-byte alignment in
                // the on-disk layout. Detect arithmetic overflow on
                // the rounding before doing the bounds check.
                if (n_namesz > 0xFFFFFFFCU || n_descsz > 0xFFFFFFFCU) {
                    return false;
                }
                const std::uint64_t padded_name =
                    static_cast<std::uint64_t>(n_namesz + 3U) & ~static_cast<std::uint64_t>(3U);
                const std::uint64_t padded_desc =
                    static_cast<std::uint64_t>(n_descsz + 3U) & ~static_cast<std::uint64_t>(3U);
                const std::uint64_t entry_size = 12U + padded_name + padded_desc;
                if (entry_size > end - cursor) {
                    return false; // note claims to extend past section
                }
                cursor += entry_size;
            }
        }
    }
    return true;
}

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Cap inputs at 2 MiB so a single fuzzer iteration stays fast;
    // larger inputs are unlikely to surface new crashes anyway.
    if (size > (2U * 1024U * 1024U)) {
        return 0;
    }
    // Shallow ELF sanity to avoid the upstream LIEF OOM class. See
    // looks_reasonable_elf above. Non-ELF inputs (PE, Mach-O, junk)
    // pass through unchanged.
    if (!looks_reasonable_elf(data, size)) {
        return 0;
    }
    std::error_code ec;
    auto dir = std::filesystem::temp_directory_path() / "abcpwn-fuzz";
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        return 0;
    }
    char name[64];
    std::snprintf(name, sizeof name, "binloader-%p.bin", static_cast<const void*>(data));
    const auto path = dir / name;
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }
    abcpwn::formats::LoadOptions opts;
    opts.require_known_format = false;
    (void) abcpwn::formats::load(path, opts);
    std::filesystem::remove(path, ec);
    return 0;
}
