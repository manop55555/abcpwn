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
    app.add_flag("-i,--interactive",
                 interactive,
                 "Drop to interactive shell after script (not implemented in v0.1)");
    app.add_option("--log", log_path, "Log all I/O to this file");
    app.add_option("--timeout", timeout_seconds, "Per-recv timeout in seconds");
}

core::Result<core::CommandResult> PwnCommand::run(const core::Context& /*ctx*/) {
    auto spec = parse_target(target);
    if (!spec) {
        return core::err(spec.error());
    }
    if (spec->kind == TubeKind::Process) {
        return core::err(core::ErrorCode::Unsupported,
                         "pwn: process-mode I/O tubes require fork+exec which is "
                         "disallowed in src/ by the project's source-code rules. "
                         "Run the local binary in a separate terminal and use "
                         "`abcpwn pwn host:port` against its open socket, or wait "
                         "for a later milestone that wires posix_spawn through a "
                         "narrow shim.");
    }

    // v0.1: parse the DSL (when provided) and report a planned step
    // list rather than executing socket I/O. The actual TCP / Unix
    // socket execution path is straightforward but adds runtime
    // testing surface that does not fit this session's budget;
    // landing the parser surface now lets later sessions plug in
    // the socket driver without re-touching the DSL.
    std::vector<DslStep> steps;
    if (!script_path.empty()) {
        auto src = core::safe_io::read_text_file(script_path);
        if (!src) {
            return core::err(src.error());
        }
        auto parsed = parse_dsl(*src);
        if (!parsed) {
            return core::err(parsed.error());
        }
        steps = std::move(*parsed);
    }

    core::CommandResult res;
    auto& sec = res.sections.emplace_back();
    sec.title = "pwn plan";
    sec.findings.emplace_back(core::Severity::Info, "target", target);
    sec.findings.emplace_back(core::Severity::Info,
                              "tube",
                              spec->kind == TubeKind::Tcp ? std::string("TCP ") + spec->host_or_path
                                                                + ":" + std::to_string(spec->port)
                              : spec->kind == TubeKind::UnixSocket
                                  ? std::string("Unix ") + spec->host_or_path
                                  : std::string("Process ") + spec->host_or_path);
    sec.findings.emplace_back(
        core::Severity::Info, "timeout", std::to_string(timeout_seconds) + "s");
    if (!steps.empty()) {
        auto& script = res.sections.emplace_back();
        script.title = "script steps";
        for (std::size_t i = 0; i < steps.size(); ++i) {
            const auto& s = steps[i];
            std::string label;
            switch (s.op) {
            case DslOp::RecvUntil:
                label = "recvuntil";
                break;
            case DslOp::RecvLine:
                label = "recvline";
                break;
            case DslOp::RecvN:
                label = "recvn " + std::to_string(s.numeric);
                break;
            case DslOp::Send:
                label = "send";
                break;
            case DslOp::SendLine:
                label = "sendline";
                break;
            case DslOp::Sleep:
                label = "sleep " + std::to_string(s.numeric) + "ms";
                break;
            case DslOp::Expect:
                label = "expect (regex)";
                break;
            case DslOp::Set:
                label = "set " + s.arg1 + "=" + s.arg2;
                break;
            }
            script.findings.emplace_back(core::Severity::Info,
                                         std::to_string(i) + ": " + label,
                                         s.op == DslOp::Set ? std::string{} : s.arg1);
        }
    }
    sec.findings.emplace_back(core::Severity::Info,
                              "note",
                              "v0.1 parses the target + DSL and reports the plan; socket "
                              "execution lands alongside the dispatcher in a later "
                              "milestone");
    return res;
}

} // namespace abcpwn::commands::pwn
