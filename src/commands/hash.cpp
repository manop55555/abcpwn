// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/hash.hpp"

#include "abcpwn/core/safe_io.hpp"

#include <picosha2.h>

#include <CLI/CLI.hpp>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace abcpwn::commands {

std::string sha256_hex(std::span<const std::uint8_t> data) {
    return picosha2::hash256_hex_string(data.begin(), data.end());
}

void HashCommand::setup(CLI::App& app) {
    app.add_option("targets", targets, "Files to hash")->required();
    app.add_option("-a,--algorithm", algorithm, "Algorithm (sha256, ...)");
}

core::Result<core::CommandResult> HashCommand::run(const core::Context& ctx) {
    if (algorithm != "sha256") {
        return core::err(core::ErrorCode::Unsupported,
            "hash: only sha256 supported in this build "
            "(md5/sha1/sha512 land in a later milestone)");
    }
    core::CommandResult res;
    for (const auto& path : targets) {
        core::safe_io::ReadOptions opts;
        opts.max_bytes = ctx.limits.max_file_bytes;
        auto raw = core::safe_io::read_file(path, opts);
        if (!raw) {
            return core::err(raw.error());
        }
        const std::span<const std::uint8_t> view{
            reinterpret_cast<const std::uint8_t*>(raw->data()),
            raw->size(),
        };
        res.raw_lines.push_back(sha256_hex(view) + "  " + path);
    }
    return res;
}

}  // namespace abcpwn::commands
