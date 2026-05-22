// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// Placeholder source so the abcpwn_core target has at least one
// translation unit before the real source lands in step 4. Replaced
// (or kept harmlessly) once real core sources start landing.

namespace abcpwn::core {

// Anonymous-namespace symbol prevents the empty TU from being
// optimized away entirely on linkers that complain about it.
namespace {
[[maybe_unused]] constexpr int build_marker_v = 1;
} // namespace

} // namespace abcpwn::core
