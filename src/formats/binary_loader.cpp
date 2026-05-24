// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/formats/binary_loader.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <LIEF/LIEF.hpp>
#include <LIEF/logging.hpp>

#include "abcpwn/core/safe_io.hpp"

namespace abcpwn::formats {

std::string_view format_name(BinaryFormat f) noexcept {
    switch (f) {
    case BinaryFormat::Elf:
        return "ELF";
    case BinaryFormat::Pe:
        return "PE";
    case BinaryFormat::MachO:
        return "MachO";
    case BinaryFormat::Unknown:
        return "Unknown";
    }
    return "Unknown";
}

std::string_view endian_name(Endian e) noexcept {
    switch (e) {
    case Endian::Little:
        return "little";
    case Endian::Big:
        return "big";
    case Endian::Other:
        return "unknown";
    }
    return "unknown";
}

BinaryFormat sniff_format(std::string_view header) noexcept {
    if (header.size() >= 4
        && std::memcmp(header.data(),
                       "\x7f"
                       "ELF",
                       4)
               == 0) {
        return BinaryFormat::Elf;
    }
    if (header.size() >= 2 && header[0] == 'M' && header[1] == 'Z') {
        return BinaryFormat::Pe;
    }
    if (header.size() >= 4) {
        const auto u = reinterpret_cast<const unsigned char*>(header.data());
        // Mach-O magic numbers (32/64, big/little endian)
        static constexpr std::array<std::uint32_t, 4> macho_magic = {
            0xfeedface,
            0xfeedfacf,
            0xcefaedfe,
            0xcffaedfe,
        };
        const std::uint32_t v =
            static_cast<std::uint32_t>(u[0]) | (static_cast<std::uint32_t>(u[1]) << 8)
            | (static_cast<std::uint32_t>(u[2]) << 16) | (static_cast<std::uint32_t>(u[3]) << 24);
        for (const auto m : macho_magic) {
            if (v == m) {
                return BinaryFormat::MachO;
            }
        }
    }
    return BinaryFormat::Unknown;
}

namespace {

constexpr std::array kDangerous = {
    std::string_view{"gets"},
    std::string_view{"strcpy"},
    std::string_view{"strcat"},
    std::string_view{"sprintf"},
    std::string_view{"vsprintf"},
    std::string_view{"scanf"},
    std::string_view{"fscanf"},
    std::string_view{"sscanf"},
    std::string_view{"vscanf"},
    std::string_view{"system"},
    std::string_view{"popen"},
    std::string_view{"execl"},
    std::string_view{"execv"},
    std::string_view{"execve"},
};

std::string elf_machine_to_arch(std::uint32_t m) {
    using E = LIEF::ELF::ARCH;
    switch (static_cast<E>(m)) {
    case E::I386:
        return "i386";
    case E::X86_64:
        return "x86_64";
    case E::ARM:
        return "arm";
    case E::AARCH64:
        return "aarch64";
    case E::MIPS:
        return "mips";
    case E::PPC:
        return "ppc";
    case E::PPC64:
        return "ppc64";
    case E::RISCV:
        return "riscv";
    default:
        return "unknown";
    }
}

BinaryBits bits_from_lief(LIEF::Binary& b) {
    // LIEF exposes header size mostly through format-specific objects;
    // probe via dynamic_cast.
    if (auto* e = dynamic_cast<LIEF::ELF::Binary*>(&b)) {
        return e->header().identity_class() == LIEF::ELF::Header::CLASS::ELF64 ? BinaryBits::Bits64
                                                                               : BinaryBits::Bits32;
    }
    if (auto* p = dynamic_cast<LIEF::PE::Binary*>(&b)) {
        return p->type() == LIEF::PE::PE_TYPE::PE32_PLUS ? BinaryBits::Bits64 : BinaryBits::Bits32;
    }
    if (auto* m = dynamic_cast<LIEF::MachO::Binary*>(&b)) {
        return m->header().is_64bit() ? BinaryBits::Bits64 : BinaryBits::Bits32;
    }
    return BinaryBits::Other;
}

Endian endian_from_lief(LIEF::Binary& b) {
    if (auto* e = dynamic_cast<LIEF::ELF::Binary*>(&b)) {
        return e->header().identity_data() == LIEF::ELF::Header::ELF_DATA::LSB ? Endian::Little
                                                                               : Endian::Big;
    }
    if (dynamic_cast<LIEF::PE::Binary*>(&b)) {
        return Endian::Little; // PE is little-endian by definition
    }
    if (auto* m = dynamic_cast<LIEF::MachO::Binary*>(&b)) {
        const auto magic = m->header().magic();
        return (magic == LIEF::MachO::MACHO_TYPES::MAGIC
                || magic == LIEF::MachO::MACHO_TYPES::MAGIC_64)
                   ? Endian::Little
                   : Endian::Big;
    }
    return Endian::Other;
}

std::string arch_from_lief(LIEF::Binary& b) {
    if (auto* e = dynamic_cast<LIEF::ELF::Binary*>(&b)) {
        return elf_machine_to_arch(static_cast<std::uint32_t>(e->header().machine_type()));
    }
    if (auto* p = dynamic_cast<LIEF::PE::Binary*>(&b)) {
        switch (p->header().machine()) {
        case LIEF::PE::Header::MACHINE_TYPES::AMD64:
            return "x86_64";
        case LIEF::PE::Header::MACHINE_TYPES::I386:
            return "i386";
        case LIEF::PE::Header::MACHINE_TYPES::ARM:
            return "arm";
        case LIEF::PE::Header::MACHINE_TYPES::ARM64:
            return "aarch64";
        default:
            return "unknown";
        }
    }
    if (auto* m = dynamic_cast<LIEF::MachO::Binary*>(&b)) {
        switch (m->header().cpu_type()) {
        case LIEF::MachO::Header::CPU_TYPE::ARM:
            return "arm";
        case LIEF::MachO::Header::CPU_TYPE::ARM64:
            return "aarch64";
        case LIEF::MachO::Header::CPU_TYPE::X86:
            return "i386";
        case LIEF::MachO::Header::CPU_TYPE::X86_64:
            return "x86_64";
        default:
            return "unknown";
        }
    }
    return "unknown";
}

void detect_elf_mitigations(LIEF::ELF::Binary& e, Mitigations& m) {
    bool has_gnu_relro = false;
    bool has_bind_now = false;
    for (const auto& seg : e.segments()) {
        if (seg.type() == LIEF::ELF::Segment::TYPE::GNU_RELRO) {
            has_gnu_relro = true;
        }
        if (seg.type() == LIEF::ELF::Segment::TYPE::GNU_STACK) {
            m.nx = (static_cast<std::uint32_t>(seg.flags())
                    & static_cast<std::uint32_t>(LIEF::ELF::Segment::FLAGS::X))
                   == 0;
        }
    }
    if (auto* d = e.get(LIEF::ELF::DynamicEntry::TAG::FLAGS_1)) {
        if (const auto* df = dynamic_cast<const LIEF::ELF::DynamicEntryFlags*>(d)) {
            has_bind_now = df->has(LIEF::ELF::DynamicEntryFlags::FLAG::NOW);
        }
    }
    if (e.has(LIEF::ELF::DynamicEntry::TAG::BIND_NOW)) {
        has_bind_now = true;
    }
    if (has_gnu_relro && has_bind_now) {
        m.relro = Mitigations::RelroLevel::Full;
    } else if (has_gnu_relro) {
        m.relro = Mitigations::RelroLevel::Partial;
    } else {
        m.relro = Mitigations::RelroLevel::None;
    }
    m.pie = (e.header().file_type() == LIEF::ELF::Header::FILE_TYPE::DYN);

    for (const auto& sym : e.dynamic_symbols()) {
        const auto n = sym.name();
        if (n == "__stack_chk_fail" || n == "__stack_chk_fail_local") {
            m.canary = true;
        }
        if (n.starts_with("__") && n.ends_with("_chk")) {
            m.fortify = true;
        }
    }

    if (e.has(LIEF::ELF::DynamicEntry::TAG::RPATH)) {
        m.rpath = true;
    }
    if (e.has(LIEF::ELF::DynamicEntry::TAG::RUNPATH)) {
        m.runpath = true;
    }

    // "stripped" approximated as: no symtab (debug-style) symbol table.
    m.stripped = e.symtab_symbols().empty();
}

void detect_pe_mitigations(LIEF::PE::Binary& p, Mitigations& m) {
    using DllFlag = LIEF::PE::OptionalHeader::DLL_CHARACTERISTICS;
    const auto& opt = p.optional_header();
    const auto c = opt.dll_characteristics();
    m.pie = (c & static_cast<std::uint32_t>(DllFlag::DYNAMIC_BASE)) != 0;
    m.nx = (c & static_cast<std::uint32_t>(DllFlag::NX_COMPAT)) != 0;
    // No analog of RELRO / canary surfacing through PE headers; leave
    // defaults.
    m.stripped = false;
}

void detect_macho_mitigations(LIEF::MachO::Binary& mh, Mitigations& m) {
    using HF = LIEF::MachO::Header::FLAGS;
    const auto flags = mh.header().flags();
    m.pie = (flags & static_cast<std::uint32_t>(HF::PIE)) != 0;
    m.nx = (flags & static_cast<std::uint32_t>(HF::ALLOW_STACK_EXECUTION)) == 0;
    m.stripped = false;
}

void populate_dynamic_imports(LIEF::Binary& b, std::vector<std::string>& out) {
    if (auto* e = dynamic_cast<LIEF::ELF::Binary*>(&b)) {
        for (const auto& sym : e->dynamic_symbols()) {
            const auto n = sym.name();
            if (sym.is_function() && !n.empty()) {
                out.emplace_back(n);
            }
        }
    } else if (auto* p = dynamic_cast<LIEF::PE::Binary*>(&b)) {
        for (const auto& imp : p->imports()) {
            for (const auto& ent : imp.entries()) {
                if (!ent.name().empty()) {
                    out.emplace_back(ent.name());
                }
            }
        }
    } else if (auto* mh = dynamic_cast<LIEF::MachO::Binary*>(&b)) {
        for (const auto& sym : mh->symbols()) {
            if (sym.has_binding_info() && !sym.name().empty()) {
                out.emplace_back(sym.name());
            }
        }
    }
}

} // namespace

struct LoadedBinary::Impl {
    std::unique_ptr<LIEF::Binary> binary;
    BinaryInfo info;
};

LoadedBinary::LoadedBinary() : impl_(std::make_unique<Impl>()) {}
LoadedBinary::LoadedBinary(LoadedBinary&&) noexcept = default;
LoadedBinary& LoadedBinary::operator=(LoadedBinary&&) noexcept = default;
LoadedBinary::~LoadedBinary() = default;

LIEF::Binary* LoadedBinary::binary() noexcept {
    return impl_ ? impl_->binary.get() : nullptr;
}
const LIEF::Binary* LoadedBinary::binary() const noexcept {
    return impl_ ? impl_->binary.get() : nullptr;
}
const BinaryInfo& LoadedBinary::info() const noexcept {
    return impl_->info;
}

void LoadedBinary::reset(std::unique_ptr<LIEF::Binary> b, BinaryInfo info) {
    if (!impl_) {
        impl_ = std::make_unique<Impl>();
    }
    impl_->binary = std::move(b);
    impl_->info = std::move(info);
}

namespace {

// Quiet LIEF's own logger the first time anyone calls into the loader.
// By default LIEF spams structured warnings to stderr (e.g. "Can't read
// the corrupt section table"), which leaks past our output layer and
// confuses callers piping abcpwn output into other tools. Disable the
// module globally; we surface our own Corrupted findings instead.
void quiet_lief_once() {
    [[maybe_unused]] static const bool initialised = [] {
        LIEF::logging::disable();
        return true;
    }();
}

// Cheap, upfront structural sanity check. Reject obviously-truncated
// ELFs before LIEF's lenient parser tries to interpret them. We only
// validate the e_ident bytes + the bare-minimum header size because
// LIEF handles partial section tables gracefully; the goal is just
// to convert the most common "user fed us 32 random bytes" case into
// a clean Corrupted error instead of an empty parse result.
[[nodiscard]] std::optional<std::string>
truncation_complaint(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 4) {
        return std::string{"file too small to identify format"};
    }
    if (bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') {
        if (bytes.size() < 5) {
            return std::string{"truncated ELF: missing e_ident[EI_CLASS]"};
        }
        // EI_CLASS = bytes[4]: 1 -> ELF32 (52-byte Ehdr),
        //                     2 -> ELF64 (64-byte Ehdr).
        const std::size_t min_ehdr = (bytes[4] == 2) ? 64 : 52;
        if (bytes.size() < min_ehdr) {
            return std::string{"truncated ELF: file is "} + std::to_string(bytes.size())
                   + " bytes, smaller than the " + std::to_string(min_ehdr) + "-byte ELF header";
        }
    }
    return std::nullopt;
}

} // namespace

core::Result<LoadedBinary> load(const std::filesystem::path& path, const LoadOptions& opts) {
    quiet_lief_once();

    core::safe_io::ReadOptions read_opts;
    read_opts.max_bytes = opts.max_bytes;
    auto bytes = core::safe_io::read_file(path, read_opts);
    if (!bytes) {
        return core::err(bytes.error());
    }

    std::span<const std::uint8_t> view(reinterpret_cast<const std::uint8_t*>(bytes->data()),
                                       bytes->size());
    if (auto complaint = truncation_complaint(view)) {
        return core::err(core::ErrorCode::Corrupted, path.string() + ": " + *complaint);
    }

    // Use the in-memory parser so we can apply our own size caps.
    std::vector<std::uint8_t> raw(bytes->size());
    std::memcpy(raw.data(), bytes->data(), bytes->size());
    std::unique_ptr<LIEF::Binary> parsed = LIEF::Parser::parse(raw);
    if (!parsed) {
        if (opts.require_known_format) {
            return core::err(core::ErrorCode::Corrupted,
                             path.string() + ": LIEF could not parse this file");
        }
        // fall through: still return an empty handle with unknown format
    }

    BinaryInfo info;
    info.path = path.string();
    info.file_size = bytes->size();

    const std::string_view hdr(reinterpret_cast<const char*>(bytes->data()),
                               std::min<std::size_t>(bytes->size(), 16));
    info.format = sniff_format(hdr);

    if (parsed) {
        info.bits = bits_from_lief(*parsed);
        info.endian = endian_from_lief(*parsed);
        info.arch = arch_from_lief(*parsed);
        info.entry_point = parsed->entrypoint();
        populate_dynamic_imports(*parsed, info.dynamic_imports);

        if (auto* e = dynamic_cast<LIEF::ELF::Binary*>(parsed.get())) {
            detect_elf_mitigations(*e, info.mitigations);
        } else if (auto* p = dynamic_cast<LIEF::PE::Binary*>(parsed.get())) {
            detect_pe_mitigations(*p, info.mitigations);
        } else if (auto* mh = dynamic_cast<LIEF::MachO::Binary*>(parsed.get())) {
            detect_macho_mitigations(*mh, info.mitigations);
        }

        // Match dangerous-function names with awareness of the glibc
        // versioned wrappers: __isoc99_scanf, __isoc99_fscanf, etc.
        // are the same scanf-family routines under a versioned ABI
        // symbol; the dangerous-function listing must include them.
        // glibc fortified variants like __scanf_chk are intentionally
        // NOT flagged -- those are the safer compiler-inserted form.
        auto strip_isoc_prefix = [](std::string_view n) noexcept -> std::string_view {
            // Match __isoc<digits>_ prefix.
            constexpr std::string_view kIso = "__isoc";
            if (n.size() <= kIso.size() + 1 || n.substr(0, kIso.size()) != kIso) {
                return n;
            }
            std::size_t i = kIso.size();
            while (i < n.size() && n[i] >= '0' && n[i] <= '9') {
                ++i;
            }
            if (i < n.size() && n[i] == '_' && i + 1 < n.size()) {
                return n.substr(i + 1);
            }
            return n;
        };
        for (const auto& n : info.dynamic_imports) {
            const auto canonical = strip_isoc_prefix(n);
            for (const auto& d : kDangerous) {
                if (canonical == d) {
                    info.dangerous_functions.emplace_back(n);
                    break;
                }
            }
        }
        std::sort(info.dangerous_functions.begin(), info.dangerous_functions.end());
        info.dangerous_functions.erase(
            std::unique(info.dangerous_functions.begin(), info.dangerous_functions.end()),
            info.dangerous_functions.end());
    }

    LoadedBinary lb;
    lb.reset(std::move(parsed), std::move(info));
    return lb;
}

} // namespace abcpwn::formats
