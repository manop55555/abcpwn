// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/commands/pwn.hpp"

#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include <CLI/CLI.hpp>

#include "abcpwn/core/safe_io.hpp"

namespace abcpwn::commands::pwn {

core::Result<TubeSpec> parse_target(std::string_view target) {
    if (target.empty()) {
        return core::err(core::ErrorCode::UsageError,
                         "pwn: target must be host:port, unix:/path, or ./binary");
    }
    if (target.starts_with("unix:")) {
        TubeSpec s;
        s.kind = TubeKind::UnixSocket;
        s.host_or_path = std::string(target.substr(5));
        return s;
    }
    if (target.starts_with("./") || target.starts_with("/") || target.starts_with("../")) {
        TubeSpec s;
        s.kind = TubeKind::Process;
        s.host_or_path = std::string(target);
        return s;
    }
    // Default to host:port
    const auto colon = target.rfind(':');
    if (colon == std::string_view::npos) {
        return core::err(core::ErrorCode::InvalidInput,
                         "pwn: target needs host:port (got '" + std::string(target) + "')");
    }
    std::uint16_t port = 0;
    const auto* begin = target.data() + colon + 1;
    const auto* end = target.data() + target.size();
    const auto pr = std::from_chars(begin, end, port);
    if (pr.ec != std::errc{} || pr.ptr != end) {
        return core::err(core::ErrorCode::InvalidInput, "pwn: target port not numeric");
    }
    TubeSpec s;
    s.kind = TubeKind::Tcp;
    s.host_or_path = std::string(target.substr(0, colon));
    s.port = port;
    return s;
}

namespace {

[[nodiscard]] std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t'))
        s.remove_suffix(1);
    return s;
}

[[nodiscard]] core::Result<DslStep> parse_line(std::string_view raw, std::size_t line_no) {
    const auto trimmed = trim(raw);
    DslStep step;
    if (trimmed.empty()) {
        return core::err(core::ErrorCode::InvalidInput,
                         "pwn dsl: empty step at line " + std::to_string(line_no));
    }
    const auto first_space = trimmed.find(' ');
    const auto opname = trimmed.substr(0, first_space);
    const auto rest = first_space == std::string_view::npos ? std::string_view{}
                                                            : trim(trimmed.substr(first_space + 1));

    auto needs_arg = [&]() -> core::Result<DslStep> {
        if (rest.empty()) {
            return core::err(core::ErrorCode::InvalidInput,
                             "pwn dsl: '" + std::string(opname) + "' requires an argument (line "
                                 + std::to_string(line_no) + ")");
        }
        step.arg1 = std::string(rest);
        return step;
    };

    if (opname == "recvuntil") {
        step.op = DslOp::RecvUntil;
        return needs_arg();
    }
    if (opname == "recvline") {
        step.op = DslOp::RecvLine;
        return step;
    }
    if (opname == "send") {
        step.op = DslOp::Send;
        return needs_arg();
    }
    if (opname == "sendline") {
        step.op = DslOp::SendLine;
        return needs_arg();
    }
    if (opname == "expect") {
        step.op = DslOp::Expect;
        return needs_arg();
    }
    if (opname == "recvn" || opname == "sleep") {
        if (rest.empty()) {
            return core::err(core::ErrorCode::InvalidInput,
                             "pwn dsl: '" + std::string(opname)
                                 + "' requires a numeric argument (line " + std::to_string(line_no)
                                 + ")");
        }
        std::int64_t v = 0;
        const auto pr = std::from_chars(rest.data(), rest.data() + rest.size(), v);
        if (pr.ec != std::errc{} || pr.ptr != rest.data() + rest.size()) {
            return core::err(core::ErrorCode::InvalidInput,
                             "pwn dsl: '" + std::string(opname) + "' arg not numeric (line "
                                 + std::to_string(line_no) + ")");
        }
        step.op = (opname == "recvn") ? DslOp::RecvN : DslOp::Sleep;
        step.numeric = v;
        return step;
    }
    if (opname == "set") {
        const auto sp = rest.find(' ');
        if (sp == std::string_view::npos) {
            return core::err(core::ErrorCode::InvalidInput,
                             "pwn dsl: 'set' wants <var> <value> (line " + std::to_string(line_no)
                                 + ")");
        }
        step.op = DslOp::Set;
        step.arg1 = std::string(rest.substr(0, sp));
        step.arg2 = std::string(trim(rest.substr(sp + 1)));
        return step;
    }
    return core::err(core::ErrorCode::InvalidInput,
                     "pwn dsl: unknown op '" + std::string(opname) + "' (line "
                         + std::to_string(line_no) + ")");
}

} // namespace

core::Result<std::vector<DslStep>> parse_dsl(std::string_view source) {
    std::vector<DslStep> out;
    std::size_t line_no = 0;
    std::size_t pos = 0;
    while (pos <= source.size()) {
        ++line_no;
        const auto nl = source.find('\n', pos);
        const auto line =
            source.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        const auto trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#') {
            if (nl == std::string_view::npos)
                break;
            pos = nl + 1;
            continue;
        }
        auto step = parse_line(trimmed, line_no);
        if (!step) {
            return core::err(step.error());
        }
        out.push_back(std::move(*step));
        if (nl == std::string_view::npos)
            break;
        pos = nl + 1;
    }
    return out;
}

void PwnCommand::setup(CLI::App& app) {
    app.add_option("target", target, "host:port | unix:/path | ./local-binary")->required();
    app.add_option("-s,--script", script_path, "DSL script to run");
    // --interactive removed (QA round 1 MAJOR stub). Returns in
    // v0.2 once the tty-state-machine work lands.
    app.add_option("--log", log_path, "Log all I/O to this file");
    app.add_option("--timeout", timeout_seconds, "Per-recv timeout in seconds");
}

core::Result<core::CommandResult> PwnCommand::run(const core::Context& /*ctx*/) {
    auto spec = parse_target(target);
    if (!spec) {
        return core::err(spec.error());
    }
    // DEF-9: live process and socket I/O are not implemented in this
    // build. tcp/unix previously returned a "plan" at rc=0 -- a false
    // success, since no socket was ever opened -- and the local-binary
    // case leaked internal source-policy text ("disallowed in src/ ...
    // posix_spawn through a narrow shim"). Report NotImplemented
    // honestly for every mode until the live tube driver lands (Tier F).
    // parse_target above still validates the target, and the public
    // parse_target/parse_dsl helpers remain for that driver to reuse.
    (void) spec;
    return core::err(core::ErrorCode::NotImplemented,
                     "pwn: live process and socket I/O are not implemented in this build "
                     "yet; this command will drive local, tcp, and unix tubes in a future "
                     "release. For now drive the target with another tool (nc, socat, a "
                     "pwntools script) and use abcpwn for the offline primitives.");
}

} // namespace abcpwn::commands::pwn
