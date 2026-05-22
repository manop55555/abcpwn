// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/encoding.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace abcpwn::commands::encoding {

namespace {

constexpr char kHex[] = "0123456789abcdef";

int hex_val(char c) noexcept {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

}  // namespace

core::Result<std::vector<std::uint8_t>> pack(
    std::uint64_t value, unsigned width, Endian endian)
{
    if (width != 1 && width != 2 && width != 4 && width != 8) {
        return core::err(core::ErrorCode::InvalidInput,
            "pack: width must be 1, 2, 4, or 8");
    }
    std::vector<std::uint8_t> out(width);
    for (unsigned i = 0; i < width; ++i) {
        const unsigned shift = (endian == Endian::Little)
            ? (i * 8U)
            : ((width - 1 - i) * 8U);
        out[i] = static_cast<std::uint8_t>((value >> shift) & 0xffU);
    }
    return out;
}

core::Result<std::uint64_t> unpack(
    std::span<const std::uint8_t> bytes, Endian endian)
{
    if (bytes.size() != 1 && bytes.size() != 2
        && bytes.size() != 4 && bytes.size() != 8)
    {
        return core::err(core::ErrorCode::InvalidInput,
            "unpack: byte count must be 1, 2, 4, or 8");
    }
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const unsigned shift = (endian == Endian::Little)
            ? (static_cast<unsigned>(i) * 8U)
            : (static_cast<unsigned>(bytes.size() - 1 - i) * 8U);
        v |= (static_cast<std::uint64_t>(bytes[i]) << shift);
    }
    return v;
}

std::string hex_encode(std::span<const std::uint8_t> bytes, std::string_view delim) {
    std::string out;
    out.reserve(bytes.size() * (2 + delim.size()));
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i != 0 && !delim.empty()) {
            out.append(delim);
        }
        out.push_back(kHex[(bytes[i] >> 4) & 0xfU]);
        out.push_back(kHex[bytes[i] & 0xfU]);
    }
    return out;
}

core::Result<std::vector<std::uint8_t>> hex_decode(std::string_view text) {
    std::vector<std::uint8_t> out;
    int nibble = -1;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-' || c == ',') {
            continue;
        }
        const int v = hex_val(c);
        if (v < 0) {
            return core::err(core::ErrorCode::InvalidInput,
                std::string("hex: invalid char '") + c + "'");
        }
        if (nibble < 0) {
            nibble = v;
        } else {
            out.push_back(static_cast<std::uint8_t>((nibble << 4) | v));
            nibble = -1;
        }
    }
    if (nibble >= 0) {
        return core::err(core::ErrorCode::InvalidInput,
            "hex: odd number of hex digits");
    }
    return out;
}

namespace {

constexpr char b64_alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_val(char c) noexcept {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

}  // namespace

std::string base64_encode(std::span<const std::uint8_t> bytes) {
    std::string out;
    out.reserve(((bytes.size() + 2) / 3) * 4);
    std::size_t i = 0;
    for (; i + 3 <= bytes.size(); i += 3) {
        const std::uint32_t v = (static_cast<std::uint32_t>(bytes[i]) << 16) |
                                (static_cast<std::uint32_t>(bytes[i + 1]) << 8) |
                                 static_cast<std::uint32_t>(bytes[i + 2]);
        out.push_back(b64_alphabet[(v >> 18) & 0x3fU]);
        out.push_back(b64_alphabet[(v >> 12) & 0x3fU]);
        out.push_back(b64_alphabet[(v >> 6)  & 0x3fU]);
        out.push_back(b64_alphabet[v         & 0x3fU]);
    }
    if (i < bytes.size()) {
        std::uint32_t v = static_cast<std::uint32_t>(bytes[i]) << 16;
        std::size_t tail = bytes.size() - i;
        if (tail > 1) {
            v |= static_cast<std::uint32_t>(bytes[i + 1]) << 8;
        }
        out.push_back(b64_alphabet[(v >> 18) & 0x3fU]);
        out.push_back(b64_alphabet[(v >> 12) & 0x3fU]);
        out.push_back(tail == 2 ? b64_alphabet[(v >> 6) & 0x3fU] : '=');
        out.push_back('=');
    }
    return out;
}

core::Result<std::vector<std::uint8_t>> base64_decode(std::string_view text) {
    std::vector<std::uint8_t> out;
    int  buf = 0;
    int  bits = 0;
    bool saw_pad = false;
    for (char c : text) {
        if (std::isspace(static_cast<unsigned char>(c))) continue;
        if (c == '=') {
            saw_pad = true;
            continue;
        }
        if (saw_pad) {
            return core::err(core::ErrorCode::InvalidInput,
                "base64: data after padding");
        }
        const int v = b64_val(c);
        if (v < 0) {
            return core::err(core::ErrorCode::InvalidInput,
                std::string("base64: invalid char '") + c + "'");
        }
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xffU));
        }
    }
    return out;
}

std::vector<std::uint8_t> xor_with_key(
    std::span<const std::uint8_t> bytes,
    std::span<const std::uint8_t> key) noexcept
{
    std::vector<std::uint8_t> out(bytes.size());
    if (key.empty()) {
        std::copy(bytes.begin(), bytes.end(), out.begin());
        return out;
    }
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        out[i] = static_cast<std::uint8_t>(bytes[i] ^ key[i % key.size()]);
    }
    return out;
}

namespace {

constexpr std::array<ErrnoEntry, 36> kErrnoTable = {{
    {1,  "EPERM",   "Operation not permitted"},
    {2,  "ENOENT",  "No such file or directory"},
    {3,  "ESRCH",   "No such process"},
    {4,  "EINTR",   "Interrupted system call"},
    {5,  "EIO",     "I/O error"},
    {6,  "ENXIO",   "No such device or address"},
    {7,  "E2BIG",   "Argument list too long"},
    {8,  "ENOEXEC", "Exec format error"},
    {9,  "EBADF",   "Bad file descriptor"},
    {10, "ECHILD",  "No child processes"},
    {11, "EAGAIN",  "Try again / resource temporarily unavailable"},
    {12, "ENOMEM",  "Out of memory"},
    {13, "EACCES",  "Permission denied"},
    {14, "EFAULT",  "Bad address"},
    {16, "EBUSY",   "Device or resource busy"},
    {17, "EEXIST",  "File exists"},
    {18, "EXDEV",   "Cross-device link"},
    {19, "ENODEV",  "No such device"},
    {20, "ENOTDIR", "Not a directory"},
    {21, "EISDIR",  "Is a directory"},
    {22, "EINVAL",  "Invalid argument"},
    {23, "ENFILE",  "Too many open files in system"},
    {24, "EMFILE",  "Too many open files (per-process)"},
    {25, "ENOTTY",  "Inappropriate ioctl for device"},
    {27, "EFBIG",   "File too large"},
    {28, "ENOSPC",  "No space left on device"},
    {29, "ESPIPE",  "Illegal seek"},
    {30, "EROFS",   "Read-only file system"},
    {31, "EMLINK",  "Too many links"},
    {32, "EPIPE",   "Broken pipe"},
    {35, "EDEADLK", "Resource deadlock would occur"},
    {38, "ENOSYS",  "Function not implemented"},
    {40, "ELOOP",   "Too many symbolic links encountered"},
    {98, "EADDRINUSE",  "Address already in use"},
    {99, "EADDRNOTAVAIL", "Cannot assign requested address"},
    {111, "ECONNREFUSED", "Connection refused"},
}};

}  // namespace

const ErrnoEntry* errno_by_number(int number) noexcept {
    for (const auto& e : kErrnoTable) {
        if (e.number == number) return &e;
    }
    return nullptr;
}

const ErrnoEntry* errno_by_name(std::string_view name) noexcept {
    for (const auto& e : kErrnoTable) {
        if (e.name == name) return &e;
    }
    return nullptr;
}

std::span<const ErrnoEntry> errno_table() noexcept {
    return kErrnoTable;
}

namespace {

constexpr std::array<Constant, 38> kConstants = {{
    // mmap PROT_*
    {"mmap", "PROT_NONE",   0},
    {"mmap", "PROT_READ",   1},
    {"mmap", "PROT_WRITE",  2},
    {"mmap", "PROT_EXEC",   4},
    // mmap MAP_*
    {"mmap", "MAP_SHARED",   0x01},
    {"mmap", "MAP_PRIVATE",  0x02},
    {"mmap", "MAP_FIXED",    0x10},
    {"mmap", "MAP_ANONYMOUS",0x20},
    // signals
    {"signal", "SIGHUP",   1},
    {"signal", "SIGINT",   2},
    {"signal", "SIGQUIT",  3},
    {"signal", "SIGILL",   4},
    {"signal", "SIGTRAP",  5},
    {"signal", "SIGABRT",  6},
    {"signal", "SIGBUS",   7},
    {"signal", "SIGFPE",   8},
    {"signal", "SIGKILL",  9},
    {"signal", "SIGSEGV", 11},
    {"signal", "SIGPIPE", 13},
    {"signal", "SIGALRM", 14},
    {"signal", "SIGTERM", 15},
    {"signal", "SIGCHLD", 17},
    {"signal", "SIGSTOP", 19},
    // auxv
    {"auxv", "AT_NULL",    0},
    {"auxv", "AT_IGNORE",  1},
    {"auxv", "AT_EXECFD",  2},
    {"auxv", "AT_PHDR",    3},
    {"auxv", "AT_PHENT",   4},
    {"auxv", "AT_PHNUM",   5},
    {"auxv", "AT_PAGESZ",  6},
    {"auxv", "AT_BASE",    7},
    {"auxv", "AT_ENTRY",   9},
    {"auxv", "AT_UID",    11},
    {"auxv", "AT_EUID",   12},
    {"auxv", "AT_GID",    13},
    {"auxv", "AT_EGID",   14},
    {"auxv", "AT_RANDOM", 25},
    {"auxv", "AT_EXECFN", 31},
}};

bool icontains(std::string_view hay, std::string_view needle) noexcept {
    if (needle.empty()) return true;
    if (needle.size() > hay.size()) return false;
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            const auto a = std::tolower(static_cast<unsigned char>(hay[i + j]));
            const auto b = std::tolower(static_cast<unsigned char>(needle[j]));
            if (a != b) { match = false; break; }
        }
        if (match) return true;
    }
    return false;
}

}  // namespace

std::vector<Constant> constgrep_search(std::string_view query, std::string_view category) noexcept {
    std::vector<Constant> out;
    for (const auto& c : kConstants) {
        if (!category.empty() && c.category != category) continue;
        if (icontains(c.name, query)) {
            out.push_back(c);
        }
    }
    return out;
}

std::span<const Constant> constgrep_table() noexcept {
    return kConstants;
}

}  // namespace abcpwn::commands::encoding
