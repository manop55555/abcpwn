# Third-Party Licenses

`abcpwn` is licensed under Apache-2.0. Which third-party libraries
this file applies to depends on which CMake flags you built with.
The default release build (`cmake --preset release`) ships *only* the
"Always-linked" set below; the optional sections document libraries
that get pulled in when you opt in to additional features at build
time. The released binary on GitHub Releases is the default-flags
build; do not assume a flag-gated library is present without
verifying via `abcpwn about features`.

## Always-linked (every build)

License composition: Apache-2.0 compatible.

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

Built only when `ABCPWN_BUILD_TESTS=ON` (the default for the `debug`
preset). These do NOT ship in the released binary.

| Library | SPDX        | Upstream                              |
|---------|-------------|---------------------------------------|
| Catch2  | BSL-1.0     | https://github.com/catchorg/Catch2    |

The Boost Software License 1.0 is Apache-2.0 compatible:
https://www.boost.org/users/license.html

## Opt-in libraries (NOT in the default release)

The libraries below are linked only when the matching `-D`
CMake flag is passed at configure time. The released `abcpwn`
binary on GitHub is built with all of these flags OFF, so it
does NOT carry their licenses or any combined-work obligations.
Run `abcpwn --version` and check the `features:` block to confirm
which flags your specific build was produced with.

### `ABCPWN_WITH_NETWORK=ON` (opt-in)

Adds libcurl for `libc download` and `pwninit`.

| Library  | SPDX           | Upstream                       |
|----------|----------------|--------------------------------|
| libcurl  | curl           | https://github.com/curl/curl   |

The curl license is MIT-derivative and Apache-2.0 compatible.

### `ABCPWN_WITH_KEYSTONE=ON` (opt-in; the `release-with-keystone` preset)

Adds the Keystone assembler engine.

| Library  | SPDX         | Upstream                                       |
|----------|--------------|------------------------------------------------|
| Keystone | GPL-2.0-only | https://github.com/keystone-engine/keystone   |

Because Keystone is GPL-2 *only* (not "or later"), a binary that
links Keystone is a combined work under GPL-2 terms. v0.1 does not
ship a pre-built Keystone-enabled release artifact; the GPL build is
produced from source via the `release-with-keystone` CMake preset
and is the responsibility of the redistributor to license-comply.

If you redistribute a Keystone-enabled build, you must comply with
GPL-2:
- Provide source code, or a written offer to provide it
- Include the GPL-2 license text
- Preserve copyright notices

### `ABCPWN_WITH_UNICORN=ON` (opt-in; no subcommand consumes this in v0.1)

Reserved for future emulation work. No v0.1 subcommand exercises
Unicorn, so even an opt-in build links a dead-code dependency
today; the flag exists so the integration can land without an ABI
break later.

| Library | SPDX         | Upstream                                  |
|---------|--------------|-------------------------------------------|
| Unicorn | GPL-2.0-only | https://github.com/unicorn-engine/unicorn |

Same GPL-2 combined-work clause as Keystone applies; same
"source-build only, not in release artifacts" caveat.

## SBOM

A CycloneDX SBOM listing every transitive dependency with its
version and license is on the v0.2 release roadmap (see
[docs/ROADMAP.md](docs/ROADMAP.md)). The v0.1 line ships SHA-256
checksums and build-provenance attestations only; the third-party
inventory above plus your vcpkg lockfile is the authoritative source
until the SBOM emitter lands.

## SPDX expression for the default release build

```
Apache-2.0 AND BSD-3-Clause AND MIT AND BSL-1.0
```

(`BSL-1.0` covers test-only dependencies that do not ship.)

## SPDX expression for a Keystone-enabled source build

```
GPL-2.0-only AND Apache-2.0 AND BSD-3-Clause AND MIT AND BSL-1.0
```

The GPL-2.0-only clause is dominant and governs distribution. This
expression applies only when you built with `ABCPWN_WITH_KEYSTONE=ON`
(see above).
