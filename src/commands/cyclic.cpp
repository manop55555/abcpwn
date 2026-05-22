// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/cyclic.hpp"

#include <algorithm>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>

namespace abcpwn::commands {

namespace {

// Standard de Bruijn generator: produces B(k, n) over alphabet of size
// k and subsequence length n. The recursion mirrors pwntools' approach
// to preserve byte-for-byte compatibility with `pwntools.cyclic`.
std::string de_bruijn(const std::string& alphabet, std::size_t n) {
    const std::size_t k = alphabet.size();
    std::vector<std::size_t> a(k * n, 0);
    std::string sequence;
    sequence.reserve(1ULL << 16);

    std::function<void(std::size_t, std::size_t)> db = [&](std::size_t t, std::size_t p) {
        if (t > n) {
            if (n % p == 0) {
                for (std::size_t j = 1; j <= p; ++j) {
                    sequence.push_back(alphabet[a[j]]);
                }
            }
        } else {
            a[t] = a[t - p];
            db(t + 1, p);
            for (std::size_t j = a[t - p] + 1; j < k; ++j) {
                a[t] = j;
                db(t + 1, t);
            }
        }
    };
    db(1, 1);
    return sequence;
}

} // namespace

std::string
cyclic_generate(std::size_t length, std::string_view alphabet, std::size_t subseq_length) {
    if (alphabet.empty() || subseq_length == 0) {
        return {};
    }
    std::string alpha(alphabet);
    std::string seq = de_bruijn(alpha, subseq_length);
    // The de Bruijn sequence is cyclic; pwntools' cyclic returns the
    // first `length` characters of the unrolled sequence (with the
    // last (n-1) chars wrapped).
    if (length == 0) {
        return seq;
    }
    std::string out;
    out.reserve(length);
    while (out.size() < length) {
        const std::size_t take = std::min(length - out.size(), seq.size());
        out.append(seq, 0, take);
        if (out.size() < length) {
            // wrap with overlap-(n-1)
            out.append(seq.data(), std::min(seq.size(), subseq_length - 1));
        }
    }
    out.resize(length);
    return out;
}

std::optional<std::size_t>
cyclic_find(std::string_view needle, std::string_view alphabet, std::size_t subseq_length) {
    if (needle.empty() || alphabet.empty() || subseq_length == 0) {
        return std::nullopt;
    }
    if (needle.size() < subseq_length) {
        return std::nullopt;
    }
    const std::string_view probe = needle.substr(0, subseq_length);

    // Generate a long enough buffer to cover one full cycle plus the
    // overlap. The de Bruijn sequence has length k^n where k is the
    // alphabet size; for n<=8 and k<=26, that's at most ~2e11 (too
    // big for n=8). For typical CTF use (k=26, n=4 -> 456976, or
    // k=26, n=8 -> a lot), cap to a sane upper bound. The 64-bit
    // case in pwntools uses k=20 by default; we leave alphabet up
    // to the caller.
    const std::size_t k = alphabet.size();
    std::uint64_t total = 1;
    for (std::size_t i = 0; i < subseq_length; ++i) {
        if (total > (1ULL << 32)) {
            return std::nullopt;
        }
        total *= k;
    }
    auto seq = cyclic_generate(static_cast<std::size_t>(total), alphabet, subseq_length);
    auto pos = seq.find(probe);
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    return pos;
}

void CyclicCommand::setup(CLI::App& app) {
    app.add_option("length", length, "Length to generate");
    app.add_option("-n,--subseq-length", subseq_length, "Subsequence length (default 4)");
    app.add_option("-a,--alphabet", alphabet, "Alphabet (default a-z)");
    app.add_option("--find", find, "Subsequence to locate in the cyclic sequence");
}

core::Result<core::CommandResult> CyclicCommand::run(const core::Context& /*ctx*/) {
    core::CommandResult res;
    if (!find.empty()) {
        auto off = cyclic_find(find, alphabet, subseq_length);
        if (!off) {
            return core::err(core::ErrorCode::NotFound, "cyclic: subsequence not found");
        }
        res.raw_lines.push_back(std::to_string(*off));
        return res;
    }
    if (length == 0) {
        return core::err(core::ErrorCode::UsageError,
                         "cyclic: provide either a length or --find <subseq>");
    }
    res.raw_lines.push_back(cyclic_generate(length, alphabet, subseq_length));
    return res;
}

} // namespace abcpwn::commands
