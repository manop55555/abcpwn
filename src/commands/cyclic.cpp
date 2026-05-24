// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/cyclic.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>

namespace abcpwn::commands {

namespace {

// Largest k^subseq space cyclic_find will materialize to locate an
// offset (256 MiB). Past this we cannot search without risking OOM
// (DEF-7); the command reports SizeExceeded with guidance instead.
constexpr std::uint64_t kCyclicMaxFindSpace = 1ULL << 28;

// Standard de Bruijn generator: produces B(k, n) over alphabet of size
// k and subsequence length n. The recursion mirrors pwntools' approach
// to preserve byte-for-byte compatibility with `pwntools.cyclic`.
// `max_len` stops generation early: the de Bruijn bytes are produced in
// order, so the first `max_len` of them are all a caller asking for a
// short pattern needs. Without this, B(k,n) materializes k^n bytes
// regardless of the requested length -- e.g. `cyclic 10 -n 7` allocated
// ~8 GB and was OOM-killed (DEF-7).
std::string de_bruijn(const std::string& alphabet, std::size_t n, std::size_t max_len) {
    const std::size_t k = alphabet.size();
    std::vector<std::size_t> a(k * n, 0);
    std::string sequence;
    sequence.reserve(std::min<std::size_t>(max_len, 1ULL << 20));

    std::function<void(std::size_t, std::size_t)> db = [&](std::size_t t, std::size_t p) {
        if (sequence.size() >= max_len) {
            return; // produced enough; stop the recursion
        }
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
    // Only generate as many bytes as the caller will use; length==0 means
    // the whole sequence, so it is unbounded (DEF-7). The CLI rejects
    // length==0, and cyclic_find passes a bounded total, so the unbounded
    // path is not reachable with a dangerous subseq length.
    const std::size_t max_len = (length == 0) ? std::numeric_limits<std::size_t>::max() : length;
    std::string seq = de_bruijn(alpha, subseq_length, max_len);
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
        total *= k;
        if (total > kCyclicMaxFindSpace) {
            // Space too large to materialize and search. Check AFTER the
            // multiply: the old pre-multiply check let the final product
            // (e.g. 26^7) escape and then OOM-killed the process (DEF-7).
            return std::nullopt;
        }
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

namespace {

// pwntools accepts integers as well as byte strings for cyclic_find:
// `cyclic_find(0x61616168)` and `cyclic_find(b'haaa')` are equivalent.
// Detect the integer form (decimal or hex 0x...) here and convert it
// to the little-endian byte representation of width = subseq_length.
// Returns std::nullopt if the input is not an integer literal.
[[nodiscard]] std::optional<std::string> needle_from_integer(std::string_view s,
                                                             std::size_t subseq_length) noexcept {
    if (s.empty() || subseq_length == 0) {
        return std::nullopt;
    }
    bool negative = false;
    std::string_view body = s;
    if (body.front() == '+' || body.front() == '-') {
        negative = (body.front() == '-');
        body.remove_prefix(1);
        if (body.empty()) {
            return std::nullopt;
        }
    }
    int base = 10;
    if (body.size() >= 2 && body[0] == '0' && (body[1] == 'x' || body[1] == 'X')) {
        base = 16;
        body.remove_prefix(2);
        if (body.empty()) {
            return std::nullopt;
        }
    }
    std::uint64_t v = 0;
    const auto* end = body.data() + body.size();
    const auto r = std::from_chars(body.data(), end, v, base);
    if (r.ec != std::errc{} || r.ptr != end) {
        return std::nullopt;
    }
    if (negative) {
        v = static_cast<std::uint64_t>(-static_cast<std::int64_t>(v));
    }
    std::string bytes(subseq_length, '\0');
    for (std::size_t i = 0; i < subseq_length; ++i) {
        bytes[i] = static_cast<char>((v >> (8 * i)) & 0xff);
    }
    return bytes;
}

} // namespace

core::Result<core::CommandResult> CyclicCommand::run(const core::Context& /*ctx*/) {
    core::CommandResult res;
    if (!find.empty()) {
        // Accept both pwntools-style integer needles (0x61616168 ->
        // little-endian bytes) and literal byte strings. The integer
        // path lets users paste a register value out of a debugger
        // straight into --find without converting to ASCII first.
        std::string needle = find;
        if (auto fi = needle_from_integer(find, subseq_length)) {
            needle = *fi;
        }
        // Guard the search space (DEF-7): cyclic_find materializes the
        // k^subseq sequence to locate the offset, so a large subseq would
        // exhaust memory. Report SizeExceeded rather than OOM or a
        // misleading "not found".
        const std::uint64_t k = std::max<std::uint64_t>(1, alphabet.size());
        std::uint64_t space = 1;
        for (std::size_t i = 0; i < subseq_length; ++i) {
            space *= k;
            if (space > kCyclicMaxFindSpace) {
                return core::err(core::ErrorCode::SizeExceeded,
                                 "cyclic: --find search space (alphabet^subseq-length) is too "
                                 "large to materialize; reduce --subseq-length or the alphabet");
            }
        }
        auto off = cyclic_find(needle, alphabet, subseq_length);
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
    // Enforce the de Bruijn unique-window guarantee: the longest
    // sequence over an alphabet of size k with unique n-length
    // windows is k^n bytes. Past that, the sequence has to repeat
    // and `cyclic --find` will return wrong offsets. Reject larger
    // requests rather than silently producing wrong output.
    const std::uint64_t k = alphabet.size();
    std::uint64_t max_length = 1;
    bool overflowed = false;
    for (std::size_t i = 0; i < subseq_length; ++i) {
        if (max_length
            > (std::numeric_limits<std::uint64_t>::max() / std::max<std::uint64_t>(1, k))) {
            overflowed = true;
            break;
        }
        max_length *= k;
    }
    if (!overflowed && length > max_length) {
        return core::err(core::ErrorCode::SizeExceeded,
                         "cyclic: length " + std::to_string(length)
                             + " exceeds the unique-window limit (alphabet^subseq = "
                             + std::to_string(max_length)
                             + "). Use -n <larger> or -a <wider alphabet> to extend.");
    }
    res.raw_lines.push_back(cyclic_generate(length, alphabet, subseq_length));
    return res;
}

} // namespace abcpwn::commands
