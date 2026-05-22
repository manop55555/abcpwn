// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>

#include "abcpwn/core/command.hpp"

namespace abcpwn::commands::iofile {

enum class Technique : std::uint8_t {
    FsopLeak = 0,
    FsopExec = 1,
    VtableOverwrite = 2,
};

// _IO_FILE_plus struct layout snapshot per libc era. Field offsets in
// bytes from the start of the struct. These shift between glibc
// versions (most notably _wide_data and vtable positions); the
// command lets the caller pick the right snapshot.
struct FileLayout {
    std::uint32_t flags_offset;
    std::uint32_t read_ptr_offset;
    std::uint32_t read_end_offset;
    std::uint32_t write_base_offset;
    std::uint32_t write_ptr_offset;
    std::uint32_t write_end_offset;
    std::uint32_t buf_base_offset;
    std::uint32_t buf_end_offset;
    std::uint32_t fileno_offset;
    std::uint32_t chain_offset; // _chain in _IO_FILE
    std::uint32_t lock_offset;
    std::uint32_t wide_data_offset;
    std::uint32_t vtable_offset; // offset of vtable pointer
    std::uint32_t struct_size;   // total size of _IO_FILE_plus
};

[[nodiscard]] FileLayout layout_for(std::string_view libc_version) noexcept;

class IofileCommand : public core::ICommand {
public:
    [[nodiscard]] std::string_view name() const noexcept override {
        return "iofile";
    }
    [[nodiscard]] std::string_view description() const noexcept override {
        return "FILE-stream exploitation helper (FSOP / vtable overwrite)";
    }
    void setup(CLI::App& app) override;
    [[nodiscard]] core::Result<core::CommandResult> run(const core::Context& ctx) override;

    std::string technique_str{};
    std::string libc_version_str{"2.34"};
};

} // namespace abcpwn::commands::iofile
