# Commands

`abcpwn` exposes 38 subcommands across 13 groups. This document is the
public reference. Every section gives synopsis, description, the key
options, one example, and the exit codes specific to the subcommand
beyond the generic [error codes](ERROR_CODES.md).

For the authoritative option list, prefer `abcpwn <sub> --help`. The
help text is generated from the same definition the binary parses, so
it never lags.

## Global options

| Option | Description |
|--------|-------------|
| `--format pretty\|json`  | Output format. `pretty` (default) is human-readable; `json` emits a stable schema. |
| `--color auto\|always\|never` | Color policy. `auto` honors `NO_COLOR` and `isatty(stdout)`. |
| `--no-color`             | Same as `--color never`. |
| `--no-banner`            | Suppress the banner on `--version` and bare invocations. |
| `--config <file>`        | Path to a TOML config file. |
| `--log-file <path>`      | Write a JSON log of the run to the given path. |
| `--allow-network`        | Permit the two network-using actions (`libc download`, `pwninit`). |
| `--help`                 | Print help. |
| `--version`              | Print version and feature flags. |

Global flags are accepted before or after the subcommand name.

## Group: recon

### `info` - mitigations, arch, symbols, libc hint

```
abcpwn info <target>
```

`checksec`-equivalent plus a libc hint. Reports NX, PIE, RELRO,
canary, fortify, stripped, RPATH and RUNPATH, plus a heuristic libc
version when symbols disambiguate.

```bash
abcpwn info ./challenge
abcpwn --format json info ./challenge | jq .findings
```

### `syms` - list symbols (dynamic, static, imports, exports)

```
abcpwn syms <target> [--type funcs|objects|imports|exports|all]
```

List symbols with optional filtering. `--type` defaults to a
sensible subset for triage.

```bash
abcpwn syms ./challenge --type funcs
```

### `strings` - list printable strings

```
abcpwn strings <target> [--min-len N]
```

Like `strings(1)` but section-aware: groups output by which section
each hit landed in.

```bash
abcpwn strings ./challenge --min-len 8
```

### `search` - search for ASCII or hex patterns

```
abcpwn search <target> <pattern> [--hex]
```

Search the binary for a literal byte sequence. `--hex` treats the
pattern as hex; otherwise it is interpreted as ASCII.

```bash
abcpwn search ./challenge --hex deadbeef
abcpwn search ./challenge 'admin'
```

### `hash` - compute file hashes

```
abcpwn hash <files>... [--algo sha256|sha1|md5]
```

Default algorithm is SHA-256. Multiple files are hashed in parallel
when the input list is large.

```bash
abcpwn hash ./libc.so.6 --algo sha256
```

## Group: encoding

### `pack` - pack an integer into raw bytes

```
abcpwn pack <value> [--width 8|16|32|64] [--endian little|big]
```

Default is 64-bit little-endian. Output is hex; pipe through `unhex`
for raw bytes.

```bash
abcpwn pack 0xdeadbeef
abcpwn pack 0xcafebabe --width 32 --endian big
```

### `unpack` - decode raw bytes into an integer

```
abcpwn unpack <hex> [--width 8|16|32|64] [--endian little|big]
```

Inverse of `pack`.

```bash
abcpwn unpack efbeadde --width 32
```

### `hex` - encode raw input as hex

```
abcpwn hex <input>
```

ASCII to hex.

```bash
abcpwn hex 'AAAA'
```

### `unhex` - decode hex bytes

```
abcpwn unhex <input>
```

Hex to raw.

```bash
abcpwn unhex 41414141
```

### `b64` - base64 encode or decode

```
abcpwn b64 <input> [--decode]
```

Encode by default. `--decode` interprets input as base64.

```bash
abcpwn b64 'AAAA'
abcpwn b64 QUFBQQ== --decode
```

### `xor` - xor against a repeating key

```
abcpwn xor <input> --key <hex>
```

Input is hex bytes; key is hex bytes. Output is hex.

```bash
abcpwn xor 41414141 --key 02
```

### `errno` - POSIX errno lookup

```
abcpwn errno [<query>]
```

`query` is a number (`2`), a name (`ENOENT`), or omitted (lists all).

```bash
abcpwn errno 11
abcpwn errno EAGAIN
abcpwn errno | grep -i no
```

### `constgrep` - search compiled-in constants

```
abcpwn constgrep <substring>
```

Greps the compiled-in tables: mmap flags, signal numbers, auxv keys,
prot bits, ELF constants. Useful for "what is the value of
`PROT_EXEC`?" without leaving the shell.

```bash
abcpwn constgrep PROT_
abcpwn constgrep AT_RANDOM
```

## Group: asm

### `asm` - assemble source text

```
abcpwn asm <source> [--arch ...] [--syntax intel|att]
```

Requires the build to be configured with `ABCPWN_WITH_KEYSTONE=ON` or
to use the `abcpwn-full` release archive. The default Apache build
exits with `FeatureDisabled` (exit 4).

```bash
abcpwn asm 'xor rdi, rdi; mov rax, 60; syscall' --arch x86_64
```

### `disasm` - disassemble raw bytes

```
abcpwn disasm <input> [--arch ...] [--syntax intel|att] [--offset N]
```

Input is hex by default; pass a file path to disassemble all
executable bytes of a file.

```bash
abcpwn disasm 4831ff48c7c03c0000000f05 --arch x86_64
```

### `phd` - pretty hex dump

```
abcpwn phd <input> [--offset N] [--length N] [--width 16|32]
```

Offset / hex / ASCII columns. Input is a file path; pass a hex
literal with the `--hex` flag to dump constructed bytes.

```bash
abcpwn phd ./challenge --offset 0x1000 --length 256
```

## Group: pattern

### `cyclic` - pwntools-style de Bruijn sequence

```
abcpwn cyclic <length>          # generate
abcpwn cyclic --search <bytes>  # search for offset
```

Compatible with `pwntools.cyclic` (alphabet, period). Lengths up to
~2.4M characters via the default alphabet.

```bash
abcpwn cyclic 200
abcpwn cyclic --search 61616168
```

## Group: rop

### `gadget` - find ROP gadgets

```
abcpwn gadget <target> [--depth N] [--type ret|jmp|call|syscall|all]
                       [--filter <regex>] [--bad-chars <hex>]
                       [--max-results N]
```

Forward-decode-at-every-byte gadget finder. Default `--depth` is 10
instructions, default `--type` is `ret`. `--filter` accepts a regex
against the gadget text; `--bad-chars` is a hex blob of bytes to
exclude (e.g. `0a00`). The default cap on unique returned gadgets is
200000; when the cap is hit the command surfaces a `gadget set
truncated` warning and the summary line names the cap so the user
knows the listing is partial. Raise the cap with `--max-results N`.

```bash
abcpwn gadget ./libc.so.6 --filter 'pop rdi'
abcpwn gadget ./libc.so.6 --depth 4 --type all --max-results 1000000
```

### `rop` - synthesize a ROP chain

```
abcpwn rop <target> --syscall N --syscall-arg ARG [--syscall-arg ARG ...]
```

Builds an x86_64 syscall chain. Supply the syscall number with
`--syscall` and zero or more arguments with repeated `--syscall-arg`
flags. The command resolves `pop rax/rdi/rsi/rdx ; ret` and a
`syscall` gadget from the target's executable sections and emits the
chain layout. Non-syscall strategies (ret2win, leak, srop-via-rop,
pwntools snippet emission) are not in v0.1; the dedicated `srop`
subcommand covers SROP, and `syms` plus manual staging covers
ret2win.

```bash
# execve("/bin/sh", 0, 0)  ->  syscall 59
abcpwn rop ./challenge --syscall 59 \
    --syscall-arg 0x404020 --syscall-arg 0 --syscall-arg 0
```

### `one-gadget` - locate `/bin/sh` string offsets in libc

```
abcpwn one-gadget <libc> [--all]
```

Locates every `/bin/sh\0` occurrence in the libc image and reports
file offsets. This is the string-locator half of the upstream Ruby
`one_gadget` tool; constraint extraction (the register / stack
preconditions that make an `execve("/bin/sh", 0, 0)` site
reachable) is not implemented. For full constraint analysis, run
the upstream `one_gadget` against the same libc.

```bash
abcpwn one-gadget ./libc.so.6
```

## Group: specialized

### `srop` - sigreturn frame builder

```
abcpwn srop --arch <arch> [field=value ...]
```

Builds an `rt_sigreturn` frame for SROP. Supports x86_64 and i386 in
v0.1.

```bash
abcpwn srop --arch x86_64 rip=0x4011aa rsp=0x404300
```

### `ret2dl` - ret2dlresolve helper

```
abcpwn ret2dl <target> <symbol>
```

Locates the dynamic linker structures (`.dynsym`, `.dynstr`,
`.rel.plt`, `_dl_runtime_resolve`) needed for a ret2dlresolve and
prints addresses, offsets, and a ready-to-use payload skeleton.

```bash
abcpwn ret2dl ./challenge system
```

### `dynelf` - leak-driven libc identification

```
abcpwn dynelf < pairs.txt
```

Reads `address value` leak pairs on stdin and matches them against
the libc database to identify the running libc. Useful when partial
leaks accumulate during exploitation.

```bash
printf 'puts 0x7f0011aabbb0\nprintf 0x7f0011aaca50\n' | abcpwn dynelf
```

### `aslr-bypass` - ASLR / PIE helpers

```
abcpwn aslr-bypass <strategy> [...]
```

`strategy` is one of: `partial-overwrite`, `brute-force-byte`,
`canary-leak`. Each strategy has its own option set; see
`abcpwn aslr-bypass <strategy> --help`.

## Group: shellcode

### `shellcode` - emit shellcode payloads

```
abcpwn shellcode --preset <name> --arch <arch>
                 [--format raw|hex|c|elf]
                 [--bad-chars <hex>]
                 [--encoder xor|alpha|null-free]
                 [--list]
```

Presets: `sh`, `read-flag`, `cat-flag`, `bind`, `reverse`. Use
`--list` to see the compiled-in table including arch coverage.

```bash
abcpwn shellcode --preset sh --arch x86_64
abcpwn shellcode --preset sh --arch x86_64 --bad-chars 00 0a
```

## Group: format string

### `fmt` - format string analysis and payload generation

```
abcpwn fmt --find-offset <leak>                        # find offset
abcpwn fmt --write <addr>=<value> [...] --offset N     # build payload
```

`--find-offset` analyzes a captured `%X.%X.%X...` leak and tells you
which positional index reaches your controlled buffer. `--write`
builds a `%hn` / `%hhn` payload that writes the given values to the
given addresses.

```bash
abcpwn fmt --find-offset 'AAAA%X.%X.%X.%X'
abcpwn fmt --write 0x404020=0x4011aa --offset 6
```

## Group: got/plt

### `got` - GOT entry listing and overwrite helper

```
abcpwn got <target> [--symbol <name>] [--overwrite <name>=<value>]
```

Lists entries with their resolved targets, or builds an overwrite
payload for a specific GOT slot.

```bash
abcpwn got ./challenge
abcpwn got ./challenge --overwrite puts=0x4011aa
```

## Group: heap

### `heap` - glibc heap exploitation primitive helper

```
abcpwn heap <technique> --libc <libc.so.6> [--target-addr <addr>]
```

`technique` is one of `tcache-poison`, `fastbin`, `house-of-force`,
`house-of-orange`, `unsorted-bin-attack`, plus a few more. The
output describes the technique's compatibility against the libc
version detected (a static technique x libc-era matrix), the
payload shape, and the safe-linking behavior if applicable.

```bash
abcpwn heap tcache-poison --libc ./libc.so.6 --target-addr 0x404300
```

### `safe-link` - encode / decode glibc safe-linking

```
abcpwn safe-link <value> <pos>
                 [--decode]
                 [--align <bytes>]
```

Implements the glibc 2.32+ safe-linking transform: `pos ^ (value >> 12)`.
`--decode` recovers `value` given the encoded fd and `pos`.

```bash
abcpwn safe-link 0x404300 0x55aabbcc
abcpwn safe-link 0x12340000 0x55aabbcc --decode
```

## Group: file/c++

### `iofile` - FILE-stream exploitation helper

```
abcpwn iofile <technique> --libc <libc.so.6> [...]
```

`technique` is one of `fsop-leak`, `fsop-exec`, `vtable-overwrite`.
Builds an `_IO_FILE` (or `_IO_FILE_plus`) layout for the named
technique. Output documents which `_IO_*` fields are touched and
which `_IO_jump_t` entry is hijacked.

```bash
abcpwn iofile fsop-exec --libc ./libc.so.6
```

### `vtable` - C++ vtable analysis and hijack helper

```
abcpwn vtable <target> [--class <name>] [--list] [--hijack <slot>=<addr>]
```

Parses Itanium C++ ABI `_ZTV*` symbols to list virtual tables; with
`--hijack` builds a payload that overwrites the given slot.

```bash
abcpwn vtable ./challenge --list
abcpwn vtable ./challenge --class MyClass --hijack 2=0x4011aa
```

## Group: sandbox

### `seccomp` - seccomp BPF analysis

```
abcpwn seccomp <action> [<input>]
```

`action`:

- `disasm` - decode a cBPF program (file or hex on stdin) to
  pseudo-assembly.
- `dump` - extract embedded seccomp filters from a binary.
- `asm` - assemble a high-level policy DSL into cBPF.
- `emu` - emulate the filter against synthetic syscalls (requires
  `ABCPWN_WITH_UNICORN=ON`).

```bash
abcpwn seccomp dump ./challenge
abcpwn seccomp disasm < filter.bpf
```

### `libc` - libc identification and inspection

```
abcpwn libc <action> [<id>]
```

`action`:

- `id` - identify libc by symbol offsets supplied via repeated
  `--offset name:value` flags.
- `offsets` - list known offsets for a given libc id.
- `diff` - diff two libc variants.
- `download` - fetch a libc archive from
  https://libc.rip (requires `--allow-network`).
- `search` - regex search over the libc database.

```bash
abcpwn libc id --offset puts:0x80 --offset printf:0x6c
abcpwn --allow-network libc download libc6_2.35-0ubuntu3_amd64
```

## Group: workflow

### `pwninit` - CTF challenge workspace setup

```
abcpwn pwninit [<directory>]
```

Sets up a typical CTF pwn workspace: detects challenge binary,
matches and (if `--allow-network`) downloads the required libc,
extracts the matching dynamic linker, patches the binary's interp,
and emits a starter `solve.py`.

```bash
abcpwn pwninit ./challenge-dir
```

### `pwn` - I/O tubes

```
abcpwn pwn <target> [--dsl <file>] [--prompt N] [--allow-network]
```

`target` is `host:port` for TCP, `unix:/path` for a unix socket, or
`./local-binary` for a process. The DSL is a simple text format with
`recvuntil`, `send`, `sendline`, `recvline`, `recvn`, `sleep`,
`expect`, and `set` directives.

```bash
abcpwn pwn 1.2.3.4:1337 --dsl solve.tube
```

### `template` - emit a solve skeleton

```
abcpwn template <strategy> <binary> [-o <out.py>]
```

`strategy`: `ret2win`, `ret2libc`, `rop`, `srop`, `fmt-leak`, `heap`.
Writes a pwntools-shaped Python skeleton tuned to the strategy and
the binary's bits/arch.

```bash
abcpwn template ret2libc ./challenge -o solve.py
```

### `diff` - byte diff between two binaries

```
abcpwn diff <file_a> <file_b>
```

Byte-by-byte diff with section context. Output groups runs of
contiguous differing bytes.

```bash
abcpwn diff ./challenge ./challenge.patched
```

### `patch` - apply byte / NOP / asm patches

```
abcpwn patch <target> [--byte 0xOFF=BYTES] [--nop A:B] [--asm-at 0xOFF='...']
```

`--byte` writes `BYTES` at `OFF`. `--nop` fills `[A, B)` with 0x90.
`--asm-at` assembles and inlines (requires Keystone). Output goes to
`<target>.patched`.

```bash
abcpwn patch ./challenge --byte 0x1234=9090
abcpwn patch ./challenge --nop 0x1240:0x1248
```

## Per-subcommand exit codes

In addition to the standard codes documented in
[ERROR_CODES.md](ERROR_CODES.md), specific subcommands surface:

- `asm`, `seccomp emu` (without Unicorn), and any feature-flag
  command in the default Apache build emit exit `4` (`FeatureDisabled`).
- `libc download`, `pwninit` without `--allow-network` emit `12`
  (`NetworkDisabled`).
- `rop` with no chain found for the requested strategy emits `10`
  (`Unsupported`).
- `gadget` and `disasm` on a corrupt section emit `11` (`Corrupted`).

## Versioning

Subcommand names, flag names, exit codes, and the JSON `schema_version`
contract are covered by semver. See [../CHANGELOG.md](../CHANGELOG.md)
and the versioning section of [../CONTRIBUTING.md](../CONTRIBUTING.md).
