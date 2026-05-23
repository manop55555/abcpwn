// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#pragma once

#include <cassert>
#include <chrono>
#include <cstdint>
#include <map>
#include <new>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "abcpwn/core/error.hpp"

namespace abcpwn::core {

// Tag type used to construct a failed Result. Mirrors std::unexpected
// just enough for our needs; we are on C++20, where std::expected is
// not yet available.
template <class E>
struct Unexpected {
    E value;

    Unexpected() = default;
    explicit Unexpected(E v) : value(std::move(v)) {}
};

template <class E>
[[nodiscard]] Unexpected<std::remove_cvref_t<E>> make_unexpected(E&& e) {
    return Unexpected<std::remove_cvref_t<E>>(std::forward<E>(e));
}

// Minimal Result<T, E> covering the slice of std::expected this
// codebase needs: in-place construction, has_value, value, error,
// operator bool, operator*, operator->. The T = void specialization
// supports "fallible operations with no return value".
template <class T, class E = Error>
class Result {
public:
    using value_type = T;
    using error_type = E;

    Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}
    Result(Unexpected<E> u) : storage_(std::in_place_index<1>, std::move(u.value)) {}

    [[nodiscard]] bool has_value() const noexcept {
        return storage_.index() == 0;
    }
    explicit operator bool() const noexcept {
        return has_value();
    }

    T& value() & {
        assert(has_value() && "value() on a failed Result");
        return std::get<0>(storage_);
    }
    const T& value() const& {
        assert(has_value() && "value() on a failed Result");
        return std::get<0>(storage_);
    }
    T&& value() && {
        return std::move(std::get<0>(storage_));
    }

    T& operator*() & noexcept {
        return std::get<0>(storage_);
    }
    const T& operator*() const& noexcept {
        return std::get<0>(storage_);
    }
    T* operator->() noexcept {
        return &std::get<0>(storage_);
    }
    const T* operator->() const noexcept {
        return &std::get<0>(storage_);
    }

    E& error() & noexcept {
        return std::get<1>(storage_);
    }
    const E& error() const& noexcept {
        return std::get<1>(storage_);
    }
    E&& error() && noexcept {
        return std::move(std::get<1>(storage_));
    }

private:
    std::variant<T, E> storage_;
};

template <class E>
class Result<void, E> {
public:
    using value_type = void;
    using error_type = E;

    Result() = default;
    Result(Unexpected<E> u) : err_(std::move(u.value)) {}

    [[nodiscard]] bool has_value() const noexcept {
        return !err_.has_value();
    }
    explicit operator bool() const noexcept {
        return has_value();
    }

    E& error() & noexcept {
        return *err_;
    }
    const E& error() const& noexcept {
        return *err_;
    }

private:
    std::optional<E> err_{};
};

// Helper that returns an Unexpected<Error> from an ErrorCode + message,
// callable from any Result-returning function regardless of T.
[[nodiscard]] inline Unexpected<Error> err(ErrorCode code, std::string message) {
    return Unexpected<Error>{Error{code, std::move(message)}};
}

[[nodiscard]] inline Unexpected<Error> err(Error e) {
    return Unexpected<Error>{std::move(e)};
}

// A single finding from a command, suitable for both pretty and JSON
// rendering. The shape mirrors STEP/10 output rules so the rendering
// layers in step 5 can consume it directly.
struct Finding {
    Severity severity{Severity::Info};
    std::string title{};
    std::string detail{};
    std::optional<std::uint64_t> offset{};
    std::optional<std::string> file{};
    std::map<std::string, std::variant<std::string, std::int64_t, bool>> extra{};

    Finding() = default;
    Finding(Severity s, std::string t) : severity(s), title(std::move(t)) {}
    Finding(Severity s, std::string t, std::string d)
        : severity(s), title(std::move(t)), detail(std::move(d)) {}
};

// A section is a labelled group of findings under a common header.
struct Section {
    std::string title{};
    std::vector<Finding> findings{};
};

// Result of running a single command. Sections carry the structured
// output; raw_lines is for commands whose output is intrinsically
// flat (`hex`, `unhex`, ...).
struct CommandResult {
    int exit_code{0};
    std::vector<Section> sections{};
    std::vector<std::string> raw_lines{};
    std::optional<std::chrono::nanoseconds> duration{};
    std::optional<std::string> summary{};
    // When true the raw_lines hold opaque binary bytes (e.g.
    // `shellcode --format raw`, `unhex`). The pretty printer
    // writes them without trailing newlines and the dispatcher
    // suppresses the duration footer + banner so stdout carries
    // exactly the payload bytes.
    bool raw_payload{false};
};

// Aggregated report from a multi-target scan (info on a directory,
// gadget search across multiple binaries, etc.). The dispatcher
// flattens this back to a CommandResult for rendering.
struct ScanReport {
    std::string target{};
    std::vector<CommandResult> results{};
    std::optional<std::chrono::nanoseconds> duration{};
};

} // namespace abcpwn::core
