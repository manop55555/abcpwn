// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// Loader-based regression for QA round 2 CRITICAL: the x86_64 sh
// preset previously pushed "/bin//sh" without a NUL terminator and
// crashed in any realistic loader. This test maps an RWX page,
// copies the bytes, forks, and jumps. If the shellcode succeeds,
// the child becomes /bin/sh; we feed it `exit 42` on stdin and
// expect the wait status to be a clean exit with code 42. Any
// SIGSEGV (the bug symptom), any non-42 exit, or a failure to
// reach execve fails the test.
//
// Linux x86_64 only. Other arches are gated out so the test
// suite stays green on CI runners we don't have inline loaders
// for.

#if defined(__linux__) && defined(__x86_64__)

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include "abcpwn/arch/arch.hpp"
#include "abcpwn/commands/shellcode.hpp"

namespace {

// Map an RWX page and copy the bytes into it. Returns the page
// address or nullptr on failure.
void* map_executable(const std::vector<std::uint8_t>& bytes) {
    void* page =
        mmap(nullptr, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        return nullptr;
    }
    std::memcpy(page, bytes.data(), bytes.size());
    return page;
}

// Write `text` to a fresh tmpfile and return its read-only fd.
int write_tmpfile(const char* text) {
    char path[] = "/tmp/abcpwn-shellcode-stdin-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) {
        return -1;
    }
    const std::size_t n = std::strlen(text);
    if (write(fd, text, n) != static_cast<ssize_t>(n)) {
        close(fd);
        unlink(path);
        return -1;
    }
    close(fd);
    int ro = open(path, O_RDONLY);
    unlink(path);
    return ro;
}

} // namespace

TEST_CASE("x86_64 sh preset actually spawns /bin/sh under a loader",
          "[shellcode][integration][linux][x86_64]") {
    using namespace abcpwn::commands::shellcode;

    PayloadSpec spec;
    spec.arch = abcpwn::arch::Arch::X86_64;
    spec.preset = Preset::Sh;
    auto p = lookup(spec);
    REQUIRE(p);
    REQUIRE_FALSE(p->bytes.empty());

    void* page = map_executable(p->bytes);
    REQUIRE(page != nullptr);

    // /bin/sh must exist for this test to be meaningful.
    if (access("/bin/sh", X_OK) != 0) {
        SKIP("/bin/sh not present; cannot verify shellcode exec");
    }

    int in_fd = write_tmpfile("exit 42\n");
    REQUIRE(in_fd >= 0);

    pid_t pid = fork();
    REQUIRE(pid >= 0);

    if (pid == 0) {
        // Child: replace stdin with the tmpfile, then call the
        // shellcode. If the shellcode succeeds, execve replaces
        // the process image with /bin/sh and the child reads
        // "exit 42\n" then exits 42. If it crashes (the bug),
        // we get a SIGSEGV which the parent observes via
        // WIFSIGNALED.
        dup2(in_fd, 0);
        close(in_fd);
        // Drop stderr/stdout to /dev/null so the spawned shell's
        // ambient output doesn't pollute the test log.
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) {
            dup2(devnull, 1);
            dup2(devnull, 2);
            close(devnull);
        }
        ((void (*)()) page)();
        // Unreached when the shellcode succeeds.
        _exit(99);
    }

    close(in_fd);

    int status = 0;
    REQUIRE(waitpid(pid, &status, 0) == pid);

    INFO("waitpid status: " << status << ", WIFEXITED=" << WIFEXITED(status)
                            << ", WEXITSTATUS=" << (WIFEXITED(status) ? WEXITSTATUS(status) : -1)
                            << ", WIFSIGNALED=" << WIFSIGNALED(status)
                            << ", WTERMSIG=" << (WIFSIGNALED(status) ? WTERMSIG(status) : -1));

    REQUIRE(WIFEXITED(status));
    REQUIRE(WEXITSTATUS(status) == 42);

    munmap(page, 4096);
}

#endif // __linux__ && __x86_64__
