# Architecture

## High-level flow

```
    CLI input
       |
       v
    main.cpp                          CLI11 parses args
       |
       v
    CommandRegistry::dispatch(args)
       |
       v
    ICommand::run() ----> formats::BinaryLoader (LIEF)
                          arch::Disasm (Capstone)
                          arch::Asm (Keystone, if enabled)
                          core::SafeIO
                          core::ResourceGuard
       |
       v
    CommandResult { sections, raw_lines, duration }
       |
       v
    output::PrettyPrinter or output::JsonWriter
       |
       v
    stdout
```

## Modules

### `core/`

Shared types: `Result<T, E>`, `Error`, `ErrorCode`, `Finding`,
`Severity`, `CommandResult`, `Context`, `SafeIO`, `ResourceGuard`,
signal handling. No dependency on any other module.

### `formats/`

LIEF wrapper. `BinaryLoader::parse()` returns a unified view over
ELF / PE / Mach-O. Lazy parsing through LIEF's `ParserConfig`.

### `arch/`

Per-arch logic: syscall tables, disassembler (Capstone), assembler
(Keystone, optional). Capstone handles are cached thread-locally
per (arch, mode) tuple.

### `commands/`

The 38 subcommand implementations. Each inherits from `ICommand`
and returns a `Result<CommandResult, Error>`.

### `output/`

Pretty and JSON printers. Banner. ANSI color handling with `NO_COLOR`
and `isatty` detection.

## Module dependency graph

```
    main.cpp
       |
       +---> commands/*
                |
                +---> formats/binary_loader
                +---> arch/*
                +---> core/*
                +---> output/*
```

No circular dependencies. `core/` has no internal dependencies.

## Performance principles

- Lazy parsing through LIEF's `ParserConfig`; each command requests
  only the sections it needs.
- No allocations in hot loops. Reserve capacity up front.
- Parallel work only where justified (gadget search; multi-file
  hashing; libc DB scan). Capped at 8 threads to avoid overhead on
  small inputs.
- Stack buffers preferred over heap for small data.
- Disassembly handles cached per (arch, mode).

See [PERFORMANCE.md](PERFORMANCE.md) for measurement methodology and
benchmark numbers.

## Error handling

| Class            | Outcome                                     | Exit |
|------------------|---------------------------------------------|------|
| Bad CLI usage    | `Result<_, UsageError>`                     | 2    |
| Internal bug     | `Result<_, InternalError>` (terminate path) | 3    |
| Feature disabled | `Result<_, FeatureDisabled>`                | 4    |
| File errors      | `Result<_, IoError / NotFound / ...>`       | 5-7  |
| Bad input        | `Result<_, InvalidInput / Corrupted>`       | 8, 11 |
| Size cap         | `Result<_, SizeExceeded>`                   | 9    |
| Unsupported      | `Result<_, Unsupported>`                    | 10   |
| Network gated    | `Result<_, NetworkDisabled>`                | 12   |
| Cancelled        | `Result<_, Cancelled>` (SIGINT)             | 14   |

Full list: [ERROR_CODES.md](ERROR_CODES.md).

The dispatcher in `main.cpp` translates `Result` into a process exit
code via `Error::exit_code()`.

## Threading model

- Single-threaded by default.
- Multi-threaded only inside gadget search, multi-file hashing, and
  libc DB scan.
- Cancellation via an atomic flag checked periodically; SIGINT sets
  the flag and the workers unwind cleanly.
- No shared mutable state across threads.

## Output layer

Pretty output follows a section-based template:

```
 ===[ abcpwn v0.1.0 ]=== binary exploitation toolkit ===

  [section header]
    [+] some good finding
    [-] some bad finding                          [HIGH]
    [!] some warning                              [MEDIUM]
    [*] some info

                                                  (8 ms)
```

JSON output has its own `schema_version` field independent of the
abcpwn version. See [CONTRIBUTING.md](../CONTRIBUTING.md)
for the schema versioning policy.

## File layout

```
src/
  main.cpp                  CLI dispatcher
  core/                     Result, Error, Context, SafeIO
  formats/                  LIEF wrapper
  arch/                     Capstone wrapper + arch tables
  commands/                 38 subcommand implementations
  output/                   PrettyPrinter, JsonWriter, banner
include/abcpwn/             public headers (internal to this binary)
tests/
  unit/                     Catch2 unit tests
  integration/              end-to-end fixture-based tests
  fuzz/                     libFuzzer harnesses
  fixtures/                 sample binaries and libcs
benchmarks/                 Catch2 benchmarks
cmake/                      build helpers (Hardening, Sanitizers, ...)
scripts/                    pre-commit and pre-push checks
.github/workflows/          ci, sanitizers, fuzz, coverage, release
docs/                       this directory
man/                        abcpwn.1.md (source for the man page)
completions/                bash / zsh / fish shell completions
```

## What this binary is NOT

- Not a library. `include/abcpwn/` is implementation-internal; the
  public surface is the CLI.
- Not a kernel exploitation tool. Kernel ROP, KASLR bypass, syscall
  hijacking are out of scope.
- Not a browser exploitation tool. V8 / SpiderMonkey / JSC need
  their own tooling.
- Not a debugger or fuzzer. It analyzes binaries; it never executes
  them.
- Not a build system. It does not link, package, or sign binaries
  for other projects.
