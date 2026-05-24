# Building abcpwn

## Quick start

```bash
git clone https://github.com/manop55555/abcpwn
cd abcpwn

# Bootstrap vcpkg if you have not already
export VCPKG_ROOT=$HOME/vcpkg
git clone https://github.com/microsoft/vcpkg $VCPKG_ROOT
$VCPKG_ROOT/bootstrap-vcpkg.sh

# Configure and build (Apache-2.0 build; no Keystone)
cmake --preset release
cmake --build --preset release

# Or build with Keystone (GPL-2 combined work)
cmake --preset release-with-keystone
cmake --build --preset release-with-keystone

# Run tests
ctest --preset debug

# Install (optional)
sudo cmake --install build/release --prefix /usr/local
```

## Platform setup

### Ubuntu 24.04 (x86_64 or aarch64)

```bash
sudo apt update
sudo apt install -y \
  build-essential \
  cmake \
  ninja-build \
  git \
  curl \
  zip \
  unzip \
  tar \
  pkg-config

# vcpkg
export VCPKG_ROOT=$HOME/vcpkg
git clone https://github.com/microsoft/vcpkg $VCPKG_ROOT
$VCPKG_ROOT/bootstrap-vcpkg.sh

# Build
cd /path/to/abcpwn
cmake --preset release
cmake --build --preset release -j$(nproc)
```

Optional developer tooling: `cppcheck`, `shellcheck`, `include-what-you-use`,
`clang-tidy-18`, `clang-format-21`, `pre-commit`.

### macOS 13+ (Apple Silicon or Intel)

```bash
xcode-select --install
brew install cmake ninja git pkg-config

export VCPKG_ROOT=$HOME/vcpkg
git clone https://github.com/microsoft/vcpkg $VCPKG_ROOT
$VCPKG_ROOT/bootstrap-vcpkg.sh

cd /path/to/abcpwn
cmake --preset release
cmake --build --preset release -j$(sysctl -n hw.ncpu)
```

### FreeBSD 14+ (tier 2, best-effort)

```bash
pkg install cmake ninja git pkgconf curl
git clone https://github.com/microsoft/vcpkg ~/vcpkg
~/vcpkg/bootstrap-vcpkg.sh
export VCPKG_ROOT=~/vcpkg

cd /path/to/abcpwn
cmake --preset release
cmake --build --preset release
```

## CMake options

| Option | Default | Description |
|---|---|---|
| `ABCPWN_WITH_KEYSTONE` | OFF | Build with Keystone (GPL-2 combined work) |
| `ABCPWN_WITH_NETWORK`  | OFF | Build with libcurl for `libc download` and `pwninit` |
| `ABCPWN_WITH_UNICORN`  | OFF | Build with Unicorn for `seccomp emu` |
| `ABCPWN_BUILD_TESTS`   | ON  | Build the test suite |
| `ABCPWN_BUILD_FUZZERS` | OFF | Build libFuzzer harnesses (requires clang) |
| `ABCPWN_BUILD_BENCHES` | OFF | Build benchmark suite |
| `ABCPWN_BUILD_DOCS`    | ON  | Build man page and shell completions |
| `ABCPWN_SANITIZER`     | (none) | `address`, `undefined`, `thread`, `memory` |
| `ABCPWN_COVERAGE`      | OFF | Enable code coverage instrumentation |

## Build presets

| Preset | Build type | Features | Use case |
|---|---|---|---|
| `debug`                 | Debug   | Tests on                        | Daily development |
| `release`               | Release | Apache build, no Keystone       | Default distribution |
| `release-with-keystone` | Release | Keystone + network              | GPL-2 distribution variant |
| `asan`                  | Debug   | AddressSanitizer                | Memory error detection |
| `ubsan`                 | Debug   | UndefinedBehaviorSanitizer      | UB detection |
| `tsan`                  | Debug   | ThreadSanitizer                 | Concurrency bugs |
| `fuzz`                  | Debug   | libFuzzer                       | Fuzzing parsers |
| `coverage`              | Debug   | gcov instrumentation            | Coverage measurement |

## Running tests

```bash
# Full test suite (unit + integration)
ctest --preset debug --output-on-failure

# Single test
ctest --preset debug -R "test_info"

# With sanitizers
cmake --preset asan
cmake --build --preset asan
ctest --preset asan

# Fuzzing smoke (one minute per harness)
cmake --preset fuzz
cmake --build --preset fuzz
./build/fuzz/fuzz_binary_loader -max_total_time=60
./build/fuzz/fuzz_seccomp_decoder -max_total_time=60
./build/fuzz/fuzz_fmt_parser -max_total_time=60
./build/fuzz/fuzz_gadget_filter -max_total_time=60
```

## Code quality checks (run before pushing)

```bash
# All pre-push checks via the orchestrator
scripts/check-all.sh

# Or individually
scripts/check-no-emoji.sh
scripts/check-no-system.sh
scripts/check-spdx.sh
scripts/check-no-telemetry.sh
scripts/check-no-attribution.sh
scripts/check-no-spec-leak.sh
scripts/check-format.sh
scripts/check-urls.sh

# Static analysis (informational; CI runs continue-on-error)
clang-tidy-18 src/**/*.cpp -p build/release/
cppcheck --enable=all --suppressions-list=.cppcheck-suppress src/

# Coverage
cmake --preset coverage
cmake --build --preset coverage
ctest --preset coverage
lcov --capture --directory build/coverage --output-file coverage.info
genhtml coverage.info --output-directory coverage-html
```

## Installation

### From source

```bash
cmake --preset release
cmake --build --preset release
sudo cmake --install build/release --prefix /usr/local
```

The install layout:

- `/usr/local/bin/abcpwn`
- `/usr/local/share/man/man1/abcpwn.1`
- `/usr/local/share/bash-completion/completions/abcpwn`
- `/usr/local/share/zsh/vendor-completions/_abcpwn`  (default; on stock Ubuntu's `$fpath`)
  Alternative for source builds: `/usr/local/share/zsh/site-functions/_abcpwn`
- `/usr/local/share/fish/vendor_completions.d/abcpwn.fish`

### From release artifacts

Download from `https://github.com/manop55555/abcpwn/releases/latest`:

- `abcpwn-linux-x86_64.tar.gz` (the v0.1 pre-built artifact)

Pre-built archives for additional platforms are planned for v0.2:

- `abcpwn-linux-aarch64.tar.gz`
- `abcpwn-macos-arm64.tar.gz`
- `abcpwn-macos-x86_64.tar.gz`

Until those ship, build the other platforms from source (above). Each
archive contains the binary, man page, shell completions, `LICENSE`,
`LICENSE-THIRD-PARTY.md`, and `README.md`.

### Verify the release

```bash
curl -LO https://github.com/manop55555/abcpwn/releases/download/v0.1.0/abcpwn-linux-x86_64.tar.gz
curl -LO https://github.com/manop55555/abcpwn/releases/download/v0.1.0/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

Sigstore signature verification (`cosign verify-blob`) is planned for a
future release; release artifacts in the v0.1 line ship checksums only.

### One-liner install (Linux and macOS)

```bash
curl -sSL https://raw.githubusercontent.com/manop55555/abcpwn/main/scripts/install.sh | bash
```

The script detects platform and arch, downloads the matching release
archive, verifies the SHA-256, and installs to `~/.local/bin/abcpwn` by
default. Override with `--prefix=/usr/local`. The script never runs `sudo`
without an explicit prefix and never modifies system PATH silently.

## Troubleshooting

### "vcpkg manifest install failed"

vcpkg baseline mismatch or network glitch.

```bash
cd $VCPKG_ROOT
git pull
cd /path/to/abcpwn
rm -rf build/ vcpkg_installed/
cmake --preset release
```

### "LIEF: undefined reference to ..."

LIEF version mismatch. Ensure 0.17.6 or newer.

### "Keystone: not found" with `ABCPWN_WITH_KEYSTONE=ON`

Keystone is fetched and built via FetchContent on the first build; it can
take 5 to 10 minutes to compile from source. Check that
`build/<preset>/_deps/keystone-src/` exists; if not, FetchContent is still
working.

### macOS "ld: warning: object file was built for newer macOS version"

`CMAKE_OSX_DEPLOYMENT_TARGET` mismatch with a vcpkg dep. The presets set
this to 13.0; ensure vcpkg deps were built with the same target. Rebuild
with `rm -rf build/ vcpkg_installed/ && cmake --preset release`.

### macOS Apple Silicon "killed: 9" on first run

Gatekeeper quarantine on downloaded binaries.

```bash
xattr -d com.apple.quarantine ./abcpwn
```

The one-liner installer handles this automatically.

### Linux "error while loading shared libraries: libstdc++.so.6"

The local build was linked against newer libstdc++ than the runtime
provides. Install a matching libstdc++ or use the statically-linked
release binary from GitHub Releases.

### Out of memory during compilation

LIEF, Capstone, and Keystone together need around 4 GB RAM to compile in
parallel. Build with fewer jobs:

```bash
cmake --build --preset release -j 2
```

or use ccache:

```bash
cmake --preset release -DCMAKE_CXX_COMPILER_LAUNCHER=ccache
```

## Profiling

### Linux: perf

```bash
cmake --preset release -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer"
cmake --build --preset release
perf record -g ./build/release/abcpwn gadget libc.so.6
perf report --stdio | head -50
```

### Linux: callgrind

```bash
valgrind --tool=callgrind ./build/release/abcpwn info /bin/ls
kcachegrind callgrind.out.<pid>
```

### Linux: heaptrack or massif

```bash
valgrind --tool=massif ./build/release/abcpwn gadget libc.so.6
ms_print massif.out.<pid>
```

### macOS: Instruments

```bash
xcrun xctrace record --template "Time Profiler" \
  --launch ./build/release/abcpwn -- gadget libc.so.6
```

## Reproducible build

The release workflow pins all dependency versions and sets
`-ffile-prefix-map` plus `SOURCE_DATE_EPOCH` from the git commit
timestamp, so the resulting binary is intended to be byte-identical when
rebuilt on the same OS, compiler, and arch:

```bash
cmake --preset release \
  -DCMAKE_C_FLAGS="-ffile-prefix-map=$(pwd)=." \
  -DCMAKE_CXX_FLAGS="-ffile-prefix-map=$(pwd)=." \
  -DCMAKE_LINK_FLAGS="-Wl,--build-id=none"
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) cmake --build --preset release
diffoscope ./build/release/abcpwn /path/to/downloaded-abcpwn
```
