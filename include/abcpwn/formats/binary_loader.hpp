// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "abcpwn/core/result.hpp"

// Forward declarations to keep LIEF out of the public header so that
// command headers don't pull the entire LIEF interface in.
namespace LIEF {
class Binary;
} // namespace LIEF

namespace abcpwn::formats {

enum class BinaryFormat : std::uint8_t {
    Unknown = 0,
    Elf = 1,
    Pe = 2,
    MachO = 3,
};

enum class BinaryBits : std::uint8_t {
    Bits32 = 32,
    Bits64 = 64,
    Other = 0,
};

enum class Endian : std::uint8_t {
    Little = 0,
    Big = 1,
    Other = 2,
};

[[nodiscard]] std::string_view format_name(BinaryFormat f) noexcept;
[[nodiscard]] std::string_view endian_name(Endian e) noexcept;

// Mitigations as surfaced by the `info` command and the JSON envelope.
struct Mitigations {
    enum class RelroLevel : std::uint8_t { None = 0, Partial = 1, Full = 2 };
    RelroLevel relro{RelroLevel::None};
    bool canary{false};
    bool nx{false};
    bool pie{false};
    bool fortify{false};
    bool rpath{false};
    bool runpath{false};
    bool stripped{false};
};

// Compact set of facts the info / syms / search / hash commands need.
// More expensive queries (per-symbol metadata, per-section bytes) are
// exposed via the wrapped LIEF::Binary handle accessible through the
// loader, when callers need them.
struct BinaryInfo {
    std::string path{};
    BinaryFormat format{BinaryFormat::Unknown};
    BinaryBits bits{BinaryBits::Other};
    Endian endian{Endian::Other};
    std::string arch{}; // e.g., "x86_64", "aarch64", "arm", "mips"
    std::uint64_t entry_point{0};
    std::uintmax_t file_size{0};
    Mitigations mitigations{};
    std::vector<std::string> dynamic_imports{};
    std::vector<std::string> dangerous_functions{};
};

// Opaque RAII handle owning the parsed LIEF::Binary.
class LoadedBinary {
public:
    LoadedBinary();
    LoadedBinary(LoadedBinary&&) noexcept;
    LoadedBinary& operator=(LoadedBinary&&) noexcept;
    LoadedBinary(const LoadedBinary&) = delete;
    LoadedBinary& operator=(const LoadedBinary&) = delete;
    ~LoadedBinary();

    [[nodiscard]] LIEF::Binary* binary() noexcept;
    [[nodiscard]] const LIEF::Binary* binary() const noexcept;
    [[nodiscard]] const BinaryInfo& info() const noexcept;

    // Internal: set during load(). Not for general use.
    void reset(std::unique_ptr<LIEF::Binary> b, BinaryInfo info);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct LoadOptions {
    std::size_t max_bytes{0}; // 0 = honor caller's Context::limits
    bool require_known_format{true};
};

// Load and inspect a binary on disk. Returns a populated LoadedBinary
// (or an error). The loader never executes the binary and never opens
// the network; it only parses the on-disk bytes.
[[nodiscard]] core::Result<LoadedBinary> load(const std::filesystem::path& path,
                                              const LoadOptions& opts = {});

// Lightweight format sniff that does not pull in LIEF. Useful when
// callers only need to dispatch on format (e.g., strings command).
[[nodiscard]] BinaryFormat sniff_format(std::string_view header) noexcept;

} // namespace abcpwn::formats
