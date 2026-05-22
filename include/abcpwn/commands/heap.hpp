// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/result.hpp"

namespace abcpwn::commands::heap {

enum class Technique : std::uint8_t {
    TcachePoison = 0,
    Fastbin = 1,
    HouseOfForce = 2,
    HouseOfOrange = 3,
    HouseOfApple = 4,
    UnsortedBin = 5,
};

// Coarse libc version classes the matrix tracks. Per STEP/14 the
// supported values are 2.27, 2.31, 2.34, 2.39 -- a representative
// snapshot of the glibcs CTF challenges target. Versions outside this
// set get matched to the nearest lower entry for compatibility purposes
// and tagged as "approximate" in the output.
enum class LibcEra : std::uint8_t {
    V2_23 = 0, // 2.23 (Ubuntu 16.04)
    V2_27 = 1, // 2.27 (Ubuntu 18.04, tcache introduced 2.26)
    V2_31 = 2, // 2.31 (Ubuntu 20.04, double-free check added)
    V2_34 = 3, // 2.34 (Ubuntu 22.04, safe-linking established 2.32)
    V2_39 = 4, // 2.39 (Ubuntu 24.04, current)
};

enum class Status : std::uint8_t {
    Works = 0,     // technique is straightforward
    Mitigated = 1, // requires a bypass to work
    Broken = 2,    // does not work without significant rework
};

[[nodiscard]] std::optional<Technique> technique_from_string(std::string_view s) noexcept;
[[nodiscard]] std::optional<LibcEra> libc_era_from_string(std::string_view s) noexcept;
[[nodiscard]] std::string_view technique_name(Technique t) noexcept;
[[nodiscard]] std::string_view libc_era_label(LibcEra e) noexcept;
[[nodiscard]] std::string_view status_label(Status s) noexcept;

struct CompatEntry {
    Technique technique;
    LibcEra libc;
    Status status;
    std::string_view rationale; // one-line ASCII rationale
};

[[nodiscard]] std::span<const CompatEntry> compatibility_matrix() noexcept;

[[nodiscard]] CompatEntry lookup_compat(Technique t, LibcEra e) noexcept;

class HeapCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "heap";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "describe a heap exploitation primitive on a given libc";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string technique_str{};
    std::string libc_version_str{"2.34"};
    std::uint64_t target_address{0};
    bool all_libcs{false};
};

} // namespace abcpwn::commands::heap
