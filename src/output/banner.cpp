// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/output/banner.hpp"

#include <ostream>

namespace abcpwn::output {

namespace {

// Verbatim banner from STEP/02_BRAND.md. Byte-for-byte; UTF-8; LF
// line endings; trailing newline preserved. 13 visible lines.
constexpr std::string_view kBanner = R"BANNER(        P
        W           ┌─┐┌┐ ┌─┐┌─┐┬ ┬┌┐┌
        N           ├─┤├┴┐│  ├─┘│││││││
     ___|___        ┴ ┴└─┘└─┘┴  └┴┘┘└┘
       |A|
       |B|          binary exploitation toolkit  ·  v0.1.0
       |C|
       |0|          static analysis, ROP chain synthesis, shellcode
       |1|          generation, format string primitives, glibc heap
       |1|          exploitation, seccomp BPF analysis, libc fingerprint
       |0|          resolution, GOT/PLT inspection, sigreturn-oriented
       \ /          programming, and ret2dlresolve - all in a single
        '           native C++ binary. no telemetry. no auto-update.
)BANNER";

constexpr std::string_view kCompactHeader =
    " ===[ abcpwn v0.1.0 ]=== binary exploitation toolkit ===";

} // namespace

std::string_view banner_text() noexcept {
    return kBanner;
}

std::string_view compact_header() noexcept {
    return kCompactHeader;
}

void print_banner(std::ostream& os, bool color) {
    // Color wraps the whole block (per STEP/02 rule 6); the banner
    // bytes themselves are never mutated. Per-character coloring is
    // layered on once the pretty printer (step 5) is wired in.
    if (color) {
        os << "\x1b[2m";
    }
    os.write(kBanner.data(), static_cast<std::streamsize>(kBanner.size()));
    if (color) {
        os << "\x1b[0m";
    }
}

} // namespace abcpwn::output
