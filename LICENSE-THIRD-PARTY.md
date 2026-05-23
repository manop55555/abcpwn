# Third-Party Licenses

`abcpwn` is licensed under Apache-2.0. It links the following third-party
libraries. All licenses listed below are SPDX identifiers; follow the
upstream URL for the full text.

## Default build (`abcpwn`)

Always linked. License composition: Apache-2.0 compatible.

| Library          | SPDX                | Upstream                                    |
|------------------|---------------------|---------------------------------------------|
| LIEF             | Apache-2.0          | https://github.com/lief-project/LIEF        |
| Capstone         | BSD-3-Clause        | https://github.com/capstone-engine/capstone |
| CLI11            | BSD-3-Clause        | https://github.com/CLIUtils/CLI11           |
| nlohmann/json    | MIT                 | https://github.com/nlohmann/json            |
| spdlog           | MIT                 | https://github.com/gabime/spdlog            |
| PicoSHA2         | MIT                 | https://github.com/okdshin/PicoSHA2         |

The default `abcpwn` binary is a pure Apache-2.0 work; you may
redistribute it under the Apache-2.0 terms in [LICENSE](LICENSE).

## Test-only dependencies

Built only when `ABCPWN_BUILD_TESTS=ON` (the default for `debug` preset).
These do NOT ship in the released binary.

| Library | SPDX        | Upstream                              |
|---------|-------------|---------------------------------------|
| Catch2  | BSL-1.0     | https://github.com/catchorg/Catch2    |

The Boost Software License 1.0 is Apache-2.0 compatible:
https://www.boost.org/users/license.html

## Optional features

### `ABCPWN_WITH_NETWORK=ON`

Adds libcurl for `libc download` and `pwninit`.

| Library  | SPDX           | Upstream                       |
|----------|----------------|--------------------------------|
| libcurl  | curl           | https://github.com/curl/curl   |

The curl license is MIT-derivative and Apache-2.0 compatible.

### `ABCPWN_WITH_KEYSTONE=ON` (the `abcpwn-full` build)

Adds the Keystone assembler engine.

| Library  | SPDX      | Upstream                                          |
|----------|-----------|---------------------------------------------------|
| Keystone | GPL-2.0-only | https://github.com/keystone-engine/keystone    |

Because Keystone is GPL-2 *only* (not "or later"), a binary that links
Keystone is a combined work under GPL-2 terms. The `abcpwn-full` build
variant is therefore distributed under GPL-2.

If you redistribute `abcpwn-full`, you must comply with GPL-2:
- Provide source code, or a written offer to provide it
- Include the GPL-2 license text
- Preserve copyright notices

The default `abcpwn` build (without Keystone) is pure Apache-2.0 and has
no such restrictions.

### `ABCPWN_WITH_UNICORN=ON`

Adds the Unicorn CPU emulator for `seccomp emu` accuracy.

| Library | SPDX         | Upstream                                  |
|---------|--------------|-------------------------------------------|
| Unicorn | GPL-2.0-only | https://github.com/unicorn-engine/unicorn |

Same GPL-2 combined-work clause as Keystone applies.

## SBOM

A complete CycloneDX SBOM listing every transitive dependency with its
version and license is intended to be published with each release at:

  https://github.com/manop55555/abcpwn/releases

SBOM emission is part of `release.yml` and lands as `abcpwn-<version>-sbom.json`.

## SPDX expression for the default build

```
Apache-2.0 AND BSD-3-Clause AND MIT AND BSL-1.0
```

(`BSL-1.0` covers test-only dependencies that do not ship.)

## SPDX expression for the `-full` build

```
GPL-2.0-only AND Apache-2.0 AND BSD-3-Clause AND MIT AND BSL-1.0
```

The GPL-2.0-only clause is dominant and governs distribution.
