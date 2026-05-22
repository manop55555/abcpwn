// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// Stub entrypoint. The real CLI dispatcher lands in step 20.

#include "abcpwn/core/version.hpp"

#include <cstdio>

int main() {
    std::fputs("abcpwn ", stdout);
    std::fputs(abcpwn::core::version_string.data(), stdout);
    std::fputc('\n', stdout);
    return 0;
}
