// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/heap.hpp"

#include <CLI/CLI.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>

namespace abcpwn::commands::heap {

std::optional<Technique> technique_from_string(std::string_view s) noexcept {
    if (s == "tcache-poison")   return Technique::TcachePoison;
    if (s == "fastbin")         return Technique::Fastbin;
    if (s == "house-of-force")  return Technique::HouseOfForce;
    if (s == "house-of-orange") return Technique::HouseOfOrange;
    if (s == "house-of-apple")  return Technique::HouseOfApple;
    if (s == "unsorted-bin")    return Technique::UnsortedBin;
    return std::nullopt;
}

std::optional<LibcEra> libc_era_from_string(std::string_view s) noexcept {
    if (s == "2.23") return LibcEra::V2_23;
    if (s == "2.27") return LibcEra::V2_27;
    if (s == "2.31") return LibcEra::V2_31;
    if (s == "2.34") return LibcEra::V2_34;
    if (s == "2.39") return LibcEra::V2_39;
    return std::nullopt;
}

std::string_view technique_name(Technique t) noexcept {
    switch (t) {
        case Technique::TcachePoison:  return "tcache-poison";
        case Technique::Fastbin:       return "fastbin";
        case Technique::HouseOfForce:  return "house-of-force";
        case Technique::HouseOfOrange: return "house-of-orange";
        case Technique::HouseOfApple:  return "house-of-apple";
        case Technique::UnsortedBin:   return "unsorted-bin";
    }
    return "unknown";
}

std::string_view libc_era_label(LibcEra e) noexcept {
    switch (e) {
        case LibcEra::V2_23: return "2.23";
        case LibcEra::V2_27: return "2.27";
        case LibcEra::V2_31: return "2.31";
        case LibcEra::V2_34: return "2.34";
        case LibcEra::V2_39: return "2.39";
    }
    return "?";
}

std::string_view status_label(Status s) noexcept {
    switch (s) {
        case Status::Works:     return "WORKS";
        case Status::Mitigated: return "MITIGATED";
        case Status::Broken:    return "BROKEN";
    }
    return "?";
}

namespace {

// The compatibility matrix. Each row is a (technique, libc) pair with
// a status and a one-line rationale. The matrix is intentionally
// conservative: when a technique only works with a known bypass, it
// gets Mitigated; when the relevant struct/check was added in the
// runtime, it gets Broken.
constexpr std::array<CompatEntry, 30> kMatrix = {{
    // tcache-poison: tcache landed in 2.26. From 2.32 onward,
    // safe-linking obfuscates the fd pointer and requires the heap
    // base to mount a successful poison.
    {Technique::TcachePoison, LibcEra::V2_23, Status::Broken,
        "tcache not present before 2.26"},
    {Technique::TcachePoison, LibcEra::V2_27, Status::Works,
        "tcache present, no safe-linking; classic poison applies"},
    {Technique::TcachePoison, LibcEra::V2_31, Status::Mitigated,
        "tcache double-free check added 2.29; key field defeats naive double-free"},
    {Technique::TcachePoison, LibcEra::V2_34, Status::Mitigated,
        "safe-linking from 2.32 obfuscates fd; need a heap leak to mount poison"},
    {Technique::TcachePoison, LibcEra::V2_39, Status::Mitigated,
        "safe-linking + double-free key; chunk alignment check enforced"},

    // Fastbin: classic, still effective when an arbitrary write
    // into a freed chunk's fd is available. Modern glibcs check
    // the size field on alloc; the technique therefore needs a
    // fake-chunk-with-valid-size.
    {Technique::Fastbin, LibcEra::V2_23, Status::Works,
        "classic fastbin attack, no size validation enforced"},
    {Technique::Fastbin, LibcEra::V2_27, Status::Works,
        "alloc-time size check requires fake chunk to carry valid size"},
    {Technique::Fastbin, LibcEra::V2_31, Status::Works,
        "additional double-free check; still works with single overwrite"},
    {Technique::Fastbin, LibcEra::V2_34, Status::Mitigated,
        "safe-linking obfuscates fd from 2.32; needs heap leak"},
    {Technique::Fastbin, LibcEra::V2_39, Status::Mitigated,
        "safe-linking + alignment check; works only with heap base leak"},

    // House of Force: dies in 2.29 when malloc's top-chunk size
    // sanity check landed.
    {Technique::HouseOfForce, LibcEra::V2_23, Status::Works,
        "no top-chunk size check; arbitrary mmap by malloc(SIZE)"},
    {Technique::HouseOfForce, LibcEra::V2_27, Status::Works,
        "top-chunk integrity not yet enforced"},
    {Technique::HouseOfForce, LibcEra::V2_31, Status::Broken,
        "top-chunk size sanity check added in 2.29 (commit 30a17d8c)"},
    {Technique::HouseOfForce, LibcEra::V2_34, Status::Broken,
        "permanently mitigated"},
    {Technique::HouseOfForce, LibcEra::V2_39, Status::Broken,
        "permanently mitigated"},

    // House of Orange: chain unsorted-bin attack into FILE struct
    // exploitation via _IO_list_all. Works on older glibcs.
    {Technique::HouseOfOrange, LibcEra::V2_23, Status::Works,
        "classic House of Orange, vtable abuse via _IO_list_all"},
    {Technique::HouseOfOrange, LibcEra::V2_27, Status::Mitigated,
        "_IO_str_overflow vtable check added; bypass possible but painful"},
    {Technique::HouseOfOrange, LibcEra::V2_31, Status::Broken,
        "vtable validation tightened, original technique no longer flows"},
    {Technique::HouseOfOrange, LibcEra::V2_34, Status::Broken,
        "vtable + FILE struct hardening continues"},
    {Technique::HouseOfOrange, LibcEra::V2_39, Status::Broken,
        "vtable + FILE struct hardening continues"},

    // House of Apple: newer FILE-stream exploitation, viable on
    // 2.32+ once safe-linking forces this path over House of Orange.
    {Technique::HouseOfApple, LibcEra::V2_23, Status::Broken,
        "predates the libc internals the technique relies on"},
    {Technique::HouseOfApple, LibcEra::V2_27, Status::Broken,
        "_IO_wfile_jumps target not yet a useful pivot"},
    {Technique::HouseOfApple, LibcEra::V2_31, Status::Works,
        "House of Apple 2 viable, attacks _IO_wfile_jumps"},
    {Technique::HouseOfApple, LibcEra::V2_34, Status::Works,
        "primary FILE struct technique post-safe-linking"},
    {Technique::HouseOfApple, LibcEra::V2_39, Status::Mitigated,
        "_IO_wfile_overflow added integrity check; bypass-class technique"},

    // Unsorted-bin attack: writes main_arena's libc address to a
    // chosen target, classic technique remains broadly usable for
    // the libc-leak primitive variant.
    {Technique::UnsortedBin, LibcEra::V2_23, Status::Works,
        "classic unsorted-bin attack"},
    {Technique::UnsortedBin, LibcEra::V2_27, Status::Works,
        "classic unsorted-bin attack"},
    {Technique::UnsortedBin, LibcEra::V2_31, Status::Mitigated,
        "double-free check tightened; primitive remains as a libc leak"},
    {Technique::UnsortedBin, LibcEra::V2_34, Status::Mitigated,
        "bk corruption detection on unsorted bin removal"},
    {Technique::UnsortedBin, LibcEra::V2_39, Status::Mitigated,
        "additional invariant checks on chunk removal"},
}};

}  // namespace

std::span<const CompatEntry> compatibility_matrix() noexcept {
    return kMatrix;
}

CompatEntry lookup_compat(Technique t, LibcEra e) noexcept {
    for (const auto& row : kMatrix) {
        if (row.technique == t && row.libc == e) {
            return row;
        }
    }
    // Should never happen: the table is exhaustive for the v0.1
    // enum cross-product. Return a Broken sentinel so callers do not
    // have to handle nullopt at the call sites.
    return CompatEntry{t, e, Status::Broken, "no entry in v0.1 matrix"};
}

namespace {

std::string hex_str(std::uint64_t v) {
    char b[32];
    std::snprintf(b, sizeof b, "0x%lx", static_cast<unsigned long>(v));
    return std::string(b);
}

// Per-technique structural description: what the user needs to know
// about the layout (the chunk fields involved, the offsets, the
// expected primitive). These are intentionally short and stable.
std::string_view technique_description(Technique t) noexcept {
    switch (t) {
        case Technique::TcachePoison: return
            "Free a chunk twice (or overlap free chunks). Overwrite the "
            "freed chunk's fd with target. Next two allocs return target "
            "as a chunk. On 2.32+ the fd is XOR-obfuscated with "
            "(chunk_addr >> 12) -- safe-linking -- so a heap leak is "
            "required.";
        case Technique::Fastbin: return
            "Overflow a free fastbin chunk's fd pointer. The next alloc "
            "for the matching size returns the forged pointer. The "
            "forged chunk needs a valid size at offset 0x8 so malloc's "
            "size check passes. On 2.32+ the fd is safe-linked.";
        case Technique::HouseOfForce: return
            "Overflow the top chunk's size to a huge value. A "
            "malloc(target - top - 0x20) call then advances top to "
            "target, so the next malloc returns target. Killed in 2.29 "
            "by a top-chunk size sanity check.";
        case Technique::HouseOfOrange: return
            "Overflow the top-chunk size below page-rounded boundary; "
            "next malloc triggers _int_free on top, placing it in the "
            "unsorted bin. Chain into FILE struct via _IO_list_all to "
            "redirect malloc-error handling vtable. Largely killed by "
            "post-2.31 vtable hardening.";
        case Technique::HouseOfApple: return
            "FILE-stream technique targeting _IO_wfile_jumps + "
            "_wide_data. Pivot from a fake FILE pointer into a "
            "controlled execution flow. House of Apple 2 is the "
            "post-safe-linking workhorse.";
        case Technique::UnsortedBin: return
            "Overwrite the bk pointer of a freed unsorted-bin chunk to "
            "target - 0x10. On next alloc, the unlink writes main_arena "
            "+ offset to target. Excellent libc-leak primitive even "
            "when arbitrary-write is hardened.";
    }
    return "(no description)";
}

}  // namespace

void HeapCommand::setup(CLI::App& app) {
    app.add_option("technique", technique_str,
        "tcache-poison | fastbin | house-of-force | house-of-orange | "
        "house-of-apple | unsorted-bin")->required();
    app.add_option("--libc-version", libc_version_str,
        "Target libc version (2.23, 2.27, 2.31, 2.34, 2.39). Default 2.34.");
    app.add_option("--target-address", target_address,
        "Target write address (hex) for the chosen technique");
    app.add_flag("--all-libcs", all_libcs,
        "Report compatibility across every libc era in the matrix");
}

core::Result<core::CommandResult> HeapCommand::run(const core::Context& /*ctx*/) {
    const auto tech = technique_from_string(technique_str);
    if (!tech) {
        return core::err(core::ErrorCode::UsageError,
            "heap: unknown technique '" + technique_str + "'");
    }
    core::CommandResult res;

    if (all_libcs) {
        auto& sec = res.sections.emplace_back();
        sec.title = "compatibility (all libc eras)";
        for (const auto& row : compatibility_matrix()) {
            if (row.technique != *tech) continue;
            const auto sev =
                row.status == Status::Works     ? core::Severity::Info :
                row.status == Status::Mitigated ? core::Severity::Medium :
                                                  core::Severity::High;
            sec.findings.emplace_back(sev,
                std::string("glibc ") + std::string(libc_era_label(row.libc))
                    + " (" + std::string(status_label(row.status)) + ")",
                std::string(row.rationale));
        }
        return res;
    }

    const auto era = libc_era_from_string(libc_version_str);
    if (!era) {
        return core::err(core::ErrorCode::UsageError,
            "heap: unknown --libc-version '" + libc_version_str
                + "' (supported: 2.23, 2.27, 2.31, 2.34, 2.39)");
    }

    const auto row = lookup_compat(*tech, *era);
    {
        auto& sec = res.sections.emplace_back();
        sec.title = std::string(technique_name(*tech))
                  + " against glibc " + std::string(libc_era_label(*era));
        const auto sev =
            row.status == Status::Works     ? core::Severity::Info :
            row.status == Status::Mitigated ? core::Severity::Medium :
                                              core::Severity::High;
        sec.findings.emplace_back(sev, "status", std::string(status_label(row.status)));
        sec.findings.emplace_back(core::Severity::Info, "rationale",
            std::string(row.rationale));
    }
    {
        auto& sec = res.sections.emplace_back();
        sec.title = "technique";
        sec.findings.emplace_back(core::Severity::Info, "summary",
            std::string(technique_description(*tech)));
        if (target_address != 0) {
            sec.findings.emplace_back(core::Severity::Info, "target",
                hex_str(target_address));
        }
    }
    res.summary = std::string(technique_name(*tech)) + " on glibc "
                + std::string(libc_era_label(*era)) + ": "
                + std::string(status_label(row.status));
    return res;
}

}  // namespace abcpwn::commands::heap
