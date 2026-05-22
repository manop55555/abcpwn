// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// libFuzzer harness for the LIEF binary loader. Inputs are written to
// a tmpfs-backed temp file (LIEF takes a path, not a buffer) and fed
// through abcpwn::formats::load. We deliberately route via the public
// API so any size-cap, format-sniff, or LIEF-side crash surfaces under
// the harness rather than only at runtime.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "abcpwn/formats/binary_loader.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    // Cap inputs at 2 MiB so a single fuzzer iteration stays fast;
    // larger inputs are unlikely to surface new crashes anyway.
    if (size > (2U * 1024U * 1024U)) {
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
