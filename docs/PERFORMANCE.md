# Performance

`abcpwn` must feel instant. This document defines the targets,
measurement methodology, and the design principles that get us there.

## Targets

| Operation                                       | Target | Hard limit | Reference (Python or Ruby) |
|-------------------------------------------------|--------|------------|----------------------------|
| `abcpwn --version` cold start                   | < 5 ms  | 20 ms     | `from pwn import *`: ~1500 ms |
| `abcpwn cyclic 200`                             | < 5 ms  | 50 ms     | `cyclic(200)`: ~1500 ms |
| `abcpwn pack 0xdeadbeef`                        | < 5 ms  | 20 ms     | `p64(...)`: ~1500 ms |
| `abcpwn hex deadbeef`                           | < 5 ms  | 20 ms     | - |
| `abcpwn errno 11`                               | < 5 ms  | 20 ms     | - |
| `abcpwn info /bin/ls`                           | < 50 ms | 200 ms    | `checksec.sh`: ~100 ms |
| `abcpwn syms /bin/ls`                           | < 100 ms| 500 ms    | `nm` + `grep`: ~50 ms |
| `abcpwn gadget /bin/bash` (~10k gadgets)        | < 500 ms| 2000 ms   | ROPgadget: ~2 s |
| `abcpwn gadget libc.so.6` (~100k gadgets)       | < 4 s   | 5 s       | ROPgadget: ~20 s |
| `abcpwn rop --execve /bin/bash`                 | < 200 ms| 1 s       | pwntools `ROP()`: ~3 s |
| `abcpwn one-gadget libc.so.6`                   | < 100 ms| 500 ms    | `one_gadget`: ~1 s |
| `abcpwn libc id --offset puts:0x80`             | < 50 ms | 200 ms    | libc-database: ~500 ms |
| `abcpwn seccomp dump <binary>`                  | < 100 ms| 500 ms    | seccomp-tools: ~1 s |
| `abcpwn disasm 1024 bytes`                      | < 20 ms | 100 ms    | objdump: ~100 ms |
| `abcpwn shellcode --preset sh --arch x86_64`    | < 5 ms  | 50 ms     | `shellcraft`: ~2 s |
| `abcpwn fmt --find-offset 'AAAA%X.%X.%X'`       | < 10 ms | 100 ms    | - |
| `abcpwn phd 4096 bytes`                         | < 10 ms | 100 ms    | `xxd`: ~5 ms (we are not faster than xxd) |

Roughly 10x to 100x faster than the Python or Ruby equivalent for the
operations users hit most often.

## Baseline hardware

The numbers above target these reference machines (the ones the
GitHub Actions release pipeline uses):

- **Linux x86_64**: AMD EPYC 7763 (`ubuntu-24.04`), 4 vCPU, 16 GB RAM.
- **Linux aarch64**: Ampere Altra (`ubuntu-24.04-arm`), 4 vCPU,
  16 GB RAM.
- **macOS arm64**: Apple M1 (`macos-14`), 3 vCPU, 7 GB RAM.
- **macOS x86_64**: Intel Core i7 (`macos-13`), 3 vCPU, 14 GB RAM.

Local development on newer Apple Silicon machines is significantly
faster than these targets.

## Methodology

### Benchmark suite (`benchmarks/`)

The project uses Catch2's built-in benchmark feature. Each benchmark:

1. Warms up (one iteration discarded).
2. Runs ten iterations.
3. Reports median, p99, and standard deviation.

```cpp
TEST_CASE("info /bin/ls is fast", "[bench]") {
    BENCHMARK("info on /bin/ls") {
        InfoCommand cmd;
        cmd.set_binary("/bin/ls");
        return cmd.run();
    };
}
```

### Wall-clock timing in the CLI

Every command output footer includes its own duration:

```
                                                  (8 ms)
```

This is the user-visible measurement. The internal
`CommandResult::duration` field is populated by the dispatcher in
`main.cpp` around the `command->run()` call.

### Statistical method

For benchmark comparisons:

- **Median** as the primary number (resistant to outliers).
- **p99** to surface bad worst cases.
- **Standard deviation** to spot noisy benchmarks.

Two-sample comparison uses Mann-Whitney U or a simple percent change
threshold.

## Principles that get us there

### 1. Lazy parsing

LIEF's `ParserConfig` lets each command skip sections it does not
need. For example:

- `info` needs headers, dynamic section, symbols.
- `syms` needs symbol table, imports, GOT and PLT.
- `gadget` needs executable sections only.
- `strings` needs the raw bytes only (no LIEF parsing at all).

### 2. Bounded reads

`safe_io::read_all()` has a size cap. Commands that only need a
header request just the header bytes.

### 3. No allocations in hot loops

Reserve capacity up front:

```cpp
std::vector<Gadget> gadgets;
gadgets.reserve(estimated_count);
```

### 4. Avoid `std::regex` in hot paths

`std::regex` is consistently slow on most stdlib implementations.
For gadget filtering, hand-rolled matchers do simple patterns.
RE2 is a candidate for v0.2 if richer patterns are needed.

### 5. Parallel gadget search

```cpp
auto thread_count = std::min(std::thread::hardware_concurrency(), 8u);
```

Capped at eight threads to avoid context-switch overhead on small
workloads.

### 6. `std::format` for string formatting

C++20 `std::format` (with `fmt::format` as the fallback when the
toolchain lacks it).

### 7. Views, not copies

- `std::string_view` for read-only string parameters.
- `std::span<const std::byte>` for read-only byte buffers.
- Pass by `const &` for large objects.
- `std::move` when transferring ownership.

### 8. Cache disassembly handles

Capstone's `cs_open()` is expensive. The arch wrapper caches handles
thread-locally per (arch, mode) tuple.

## Cold-start budget

Target: under 10 ms for `abcpwn --version`.

Components (approximate, on the Linux x86_64 baseline):

- Process exec + dynamic linker: ~2 ms.
- libc init + global constructors: ~2 ms.
- CLI11 parsing: ~1 ms.
- Banner formatting + printing: ~2 ms.
- Total: ~7 ms, leaving 3 ms of headroom.

Static linking of libstdc++ adds about 2 ms but allows the binary to
run on any libstdc++ version. Today the binary uses dynamic linking;
a fully-static preset is a v0.2 candidate.

## Memory budget

| Workload class                 | Resident memory | Allocations |
|--------------------------------|-----------------|-------------|
| Any non-gadget-search command  | < 50 MB         | < 100       |
| `gadget` on libc (~100k items) | < 500 MB        | bounded; pre-allocated vectors |
| `seccomp emu` with Unicorn     | < 200 MB        | bounded     |

## Regression detection in CI

### Benchmark gate (release-time)

Before publishing a release, `release.yml` runs the benchmark suite,
compares against the stored baseline from the previous tagged
release, and fails the release if any benchmark regresses by more
than 20%.

Baselines live at:

```
benchmarks/baselines/
├── v0.1.0.json
└── ...
```

Each file records median, p99, and standard deviation per benchmark.

### Smoke benchmark on PR

Every PR runs the benchmark suite once and reports the numbers as a
workflow comment. Regressions are visible but do not block merge in
the v0.1 line.

## Profiling tools

See [../BUILDING.md](../BUILDING.md) for full invocations. Summary:

- **Linux**: `perf record -g`, `valgrind --tool=callgrind` for hot
  paths, `valgrind --tool=massif` for heap profiles.
- **macOS**: `xcrun xctrace record --template "Time Profiler"`.

## Optimization checklist (in order)

Before optimizing, measure. The benchmark suite shows where time
actually goes. Common pitfalls:

- Over-optimizing cold paths.
- Adding SIMD to code that is already cache-bound.
- Threading small workloads (overhead beats benefit).
- Premature template metaprogramming.

When the measurement says it matters:

1. Are we doing too much work? Skip unneeded parsing.
2. Are we allocating too much? Reserve, reuse buffers.
3. Are we copying too much? Move, use views.
4. Are we cache-unfriendly? Improve locality, pack structs.
5. Are we serial when we could be parallel? Add parallelism.
6. Are we using a slow algorithm? Change algorithm.
