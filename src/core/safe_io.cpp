// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/core/safe_io.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <random>
#include <span>
#include <string>
#include <string_view>
#include <system_error>

namespace abcpwn::core::safe_io {

namespace {

std::string strerror_safe(int e) {
    char buf[256]{};
#if defined(_GNU_SOURCE) || defined(__GLIBC__)
    const char* msg = strerror_r(e, buf, sizeof buf);
    return msg ? std::string(msg) : std::string("errno ") + std::to_string(e);
#else
    if (strerror_r(e, buf, sizeof buf) == 0) {
        return std::string(buf);
    }
    return std::string("errno ") + std::to_string(e);
#endif
}

Error make_error_from_errno(const std::filesystem::path& path, std::string_view op) {
    const int captured = errno;
    ErrorCode code = ErrorCode::IoError;
    switch (captured) {
    case ENOENT:
        code = ErrorCode::NotFound;
        break;
    case EACCES:
    case EPERM:
        code = ErrorCode::PermissionDenied;
        break;
    case EISDIR:
    case ENOTDIR:
    case ELOOP:
        code = ErrorCode::InvalidInput;
        break;
    default:
        code = ErrorCode::IoError;
        break;
    }
    return Error{
        code,
        std::string(op) + " " + path.string() + ": " + strerror_safe(captured),
    };
}

std::string random_suffix() {
    static thread_local std::mt19937_64 rng{std::random_device{}()};
    static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string out;
    out.reserve(8);
    for (int i = 0; i < 8; ++i) {
        out.push_back(alphabet[rng() % (sizeof alphabet - 1)]);
    }
    return out;
}

} // namespace

Result<std::uintmax_t> file_size(const std::filesystem::path& path) {
    std::error_code ec;
    const auto kind = std::filesystem::status(path, ec);
    if (ec) {
        errno = ec.value();
        return err(make_error_from_errno(path, "stat"));
    }
    if (!std::filesystem::is_regular_file(kind)) {
        return err(ErrorCode::InvalidInput, path.string() + ": not a regular file");
    }
    const std::uintmax_t size = std::filesystem::file_size(path, ec);
    if (ec) {
        errno = ec.value();
        return err(make_error_from_errno(path, "size"));
    }
    return size;
}

Result<std::vector<std::byte>> read_file(const std::filesystem::path& path,
                                         const ReadOptions& opts) {
    const auto sz = safe_io::file_size(path);
    if (!sz) {
        return err(sz.error());
    }
    if (opts.max_bytes > 0 && *sz > opts.max_bytes) {
        return err(ErrorCode::SizeExceeded,
                   path.string() + ": file is " + std::to_string(*sz) + " bytes, exceeds limit of "
                       + std::to_string(opts.max_bytes));
    }

    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return err(make_error_from_errno(path, "open"));
    }

    std::vector<std::byte> buf;
    buf.resize(static_cast<std::size_t>(*sz));
    if (*sz > 0) {
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(*sz));
        if (in.gcount() != static_cast<std::streamsize>(*sz)) {
            return err(ErrorCode::IoError, path.string() + ": short read");
        }
    }
    return buf;
}

Result<std::string> read_text_file(const std::filesystem::path& path, const ReadOptions& opts) {
    auto bytes = read_file(path, opts);
    if (!bytes) {
        return err(bytes.error());
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

Result<void> write_file_atomic(const std::filesystem::path& path, std::span<const std::byte> data) {
    auto parent = path.parent_path();
    if (parent.empty()) {
        parent = ".";
    }
    const std::filesystem::path tmp =
        parent / (path.filename().string() + ".tmp." + random_suffix());

    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            return err(make_error_from_errno(tmp, "open temp"));
        }
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
        }
        out.flush();
        if (!out) {
            std::error_code ec;
            std::filesystem::remove(tmp, ec);
            return err(ErrorCode::IoError, tmp.string() + ": write failed");
        }
    }

    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        std::error_code rm_ec;
        std::filesystem::remove(tmp, rm_ec);
        return err(ErrorCode::IoError, path.string() + ": rename failed (" + ec.message() + ")");
    }
    return {};
}

Result<void> write_text_file_atomic(const std::filesystem::path& path, std::string_view data) {
    return write_file_atomic(path,
                             std::span<const std::byte>{
                                 reinterpret_cast<const std::byte*>(data.data()),
                                 data.size(),
                             });
}

} // namespace abcpwn::core::safe_io
