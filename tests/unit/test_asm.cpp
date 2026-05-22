// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/arch/asm.hpp"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("assemble reports FeatureDisabled when keystone is off", "[arch][asm]") {
    using namespace abcpwn::arch;
    using namespace abcpwn::core;
    if (keystone_compiled_in()) {
        SKIP("Keystone is compiled in; the FeatureDisabled path is not active");
    }
    AsmOptions opts;
    opts.arch = Arch::X86_64;
    auto r = assemble("nop", opts);
    REQUIRE_FALSE(r);
    REQUIRE(r.error().code == ErrorCode::FeatureDisabled);
}

TEST_CASE("assemble produces bytes when keystone is on", "[arch][asm]") {
    using namespace abcpwn::arch;
    if (!keystone_compiled_in()) {
        SKIP("Keystone is not compiled in (Apache-2.0 build)");
    }
    AsmOptions opts;
    opts.arch = Arch::X86_64;
    auto r = assemble("nop; ret", opts);
    REQUIRE(r);
    REQUIRE_FALSE(r->empty());
}
