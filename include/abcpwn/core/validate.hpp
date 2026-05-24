// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <initializer_list>
#include <optional>
#include <string>
#include <string_view>

#include "abcpwn/core/error.hpp"

namespace abcpwn::core {

// Shared enum-flag validation (DEF-6 / DEF-8). If `value` is one of
// `allowed`, returns nullopt. Otherwise returns an Error(code) whose
// message is "<label> '<value>' (a|b|c)" -- e.g. label "gadget: unknown
// type" yields "gadget: unknown type 'bogus' (ret|jmp|call|syscall|all)".
// The caller picks the exit code (global flags use InvalidInput; command
// enums use UsageError, matching shellcode/heap/iofile).
[[nodiscard]] inline std::optional<Error>
validate_choice(std::string_view label,
                std::string_view value,
                std::initializer_list<std::string_view> allowed,
                ErrorCode code) {
    for (const auto candidate : allowed) {
        if (value == candidate) {
            return std::nullopt;
        }
    }
    std::string msg(label);
    msg += " '";
    msg.append(value);
    msg += "' (";
    bool first = true;
    for (const auto candidate : allowed) {
        if (!first) {
            msg += '|';
        }
        msg.append(candidate);
        first = false;
    }
    msg += ')';
    return Error{code, std::move(msg)};
}

} // namespace abcpwn::core
