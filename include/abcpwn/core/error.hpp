// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>

namespace abcpwn::core {

// Domain error codes. Each value also corresponds to the process exit
// code that the dispatcher should return when a command surfaces it.
// Values 0-3 are reserved for the conventional shell semantics so that
// `abcpwn ... && other-tool` works the way users expect.
enum class ErrorCode : std::int32_t {
    Ok = 0,              // success
    Generic = 1,         // unspecified runtime failure
    UsageError = 2,      // bad arguments / CLI misuse
    InternalError = 3,   // a bug in abcpwn itself
    FeatureDisabled = 4, // built without an optional feature (e.g. asm w/o Keystone)
    IoError = 5,
    PermissionDenied = 6,
    NotFound = 7,
    InvalidInput = 8,
    SizeExceeded = 9,     // input larger than configured limit
    Unsupported = 10,     // arch / format / platform not supported
    Corrupted = 11,       // input file is malformed
    NetworkDisabled = 12, // network attempt without --allow-network
    NetworkError = 13,
    Cancelled = 14, // interrupted by SIGINT
    Timeout = 15,
    NotImplemented = 16,
};

[[nodiscard]] constexpr std::string_view error_code_name(ErrorCode c) noexcept {
    switch (c) {
    case ErrorCode::Ok:
        return "Ok";
    case ErrorCode::Generic:
        return "Generic";
    case ErrorCode::UsageError:
        return "UsageError";
    case ErrorCode::InternalError:
        return "InternalError";
    case ErrorCode::FeatureDisabled:
        return "FeatureDisabled";
    case ErrorCode::IoError:
        return "IoError";
    case ErrorCode::PermissionDenied:
        return "PermissionDenied";
    case ErrorCode::NotFound:
        return "NotFound";
    case ErrorCode::InvalidInput:
        return "InvalidInput";
    case ErrorCode::SizeExceeded:
        return "SizeExceeded";
    case ErrorCode::Unsupported:
        return "Unsupported";
    case ErrorCode::Corrupted:
        return "Corrupted";
    case ErrorCode::NetworkDisabled:
        return "NetworkDisabled";
    case ErrorCode::NetworkError:
        return "NetworkError";
    case ErrorCode::Cancelled:
        return "Cancelled";
    case ErrorCode::Timeout:
        return "Timeout";
    case ErrorCode::NotImplemented:
        return "NotImplemented";
    }
    return "Unknown";
}

// Domain error carries a code plus a human-readable message. Pair with
// Result<T, Error> for fallible operations.
struct Error {
    ErrorCode code{ErrorCode::Generic};
    std::string message{};

    Error() = default;
    Error(ErrorCode c, std::string m) : code(c), message(std::move(m)) {}

    [[nodiscard]] std::int32_t exit_code() const noexcept {
        return static_cast<std::int32_t>(code);
    }
};

// Severity tag for findings.
enum class Severity : std::uint8_t {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
};

[[nodiscard]] constexpr std::string_view severity_name(Severity s) noexcept {
    switch (s) {
    case Severity::Info:
        return "INFO";
    case Severity::Low:
        return "LOW";
    case Severity::Medium:
        return "MEDIUM";
    case Severity::High:
        return "HIGH";
    case Severity::Critical:
        return "CRITICAL";
    }
    return "UNKNOWN";
}

} // namespace abcpwn::core
