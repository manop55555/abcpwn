// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "abcpwn/core/result.hpp"

namespace abcpwn::core::safe_io {

struct ReadOptions {
    std::size_t max_bytes{0}; // 0 = no extra cap beyond Limits
    bool binary{true};        // when false, line endings are not normalized
};

// Read the entire file at `path` into memory. Refuses to read regular
// files larger than `max_bytes` (when > 0) and refuses non-regular
// files (sockets, FIFOs, directories). Symlinks are followed.
[[nodiscard]] Result<std::vector<std::byte>> read_file(const std::filesystem::path& path,
                                                       const ReadOptions& opts = {});

// Convenience wrapper for textual content.
[[nodiscard]] Result<std::string> read_text_file(const std::filesystem::path& path,
                                                 const ReadOptions& opts = {});

// Return the size of the file at `path`, or an error.
[[nodiscard]] Result<std::uintmax_t> file_size(const std::filesystem::path& path);

// Atomic-write helper: writes to a temp file in the same directory and
// renames over the target. Does NOT create parent directories.
[[nodiscard]] Result<void> write_file_atomic(const std::filesystem::path& path,
                                             std::span<const std::byte> data);

[[nodiscard]] Result<void> write_text_file_atomic(const std::filesystem::path& path,
                                                  std::string_view data);

} // namespace abcpwn::core::safe_io
