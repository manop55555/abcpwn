// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555
//
// abcpwn CLI entrypoint. Parses global flags, wires every ICommand
// subclass under a single CLI11 root, builds the Context, dispatches
// to the selected command's run(), and renders the result through
// the pretty or JSON output layer. Exit codes flow from ErrorCode
// (see core/error.hpp) so shell pipelines work as expected.

#include "abcpwn/core/command.hpp"
#include "abcpwn/core/config.hpp"
#include "abcpwn/core/context.hpp"
#include "abcpwn/core/result.hpp"
#include "abcpwn/core/signal.hpp"
#include "abcpwn/core/validate.hpp"
#include "abcpwn/core/version.hpp"
#include "abcpwn/output/banner.hpp"
#include "abcpwn/output/json_writer.hpp"
#include "abcpwn/output/log.hpp"
#include "abcpwn/output/pretty.hpp"

// Every command surface.
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include "abcpwn/commands/aslr_bypass.hpp"
#include "abcpwn/commands/asm_cmd.hpp"
#include "abcpwn/commands/b64.hpp"
#include "abcpwn/commands/constgrep.hpp"
#include "abcpwn/commands/cyclic.hpp"
#include "abcpwn/commands/diff.hpp"
#include "abcpwn/commands/disasm.hpp"
#include "abcpwn/commands/dynelf.hpp"
#include "abcpwn/commands/errno_cmd.hpp"
#include "abcpwn/commands/fmt.hpp"
#include "abcpwn/commands/gadget.hpp"
#include "abcpwn/commands/got.hpp"
#include "abcpwn/commands/hash.hpp"
#include "abcpwn/commands/heap.hpp"
#include "abcpwn/commands/hex.hpp"
#include "abcpwn/commands/info.hpp"
#include "abcpwn/commands/iofile.hpp"
#include "abcpwn/commands/libc.hpp"
#include "abcpwn/commands/one_gadget.hpp"
#include "abcpwn/commands/pack.hpp"
#include "abcpwn/commands/patch.hpp"
#include "abcpwn/commands/phd.hpp"
#include "abcpwn/commands/pwn.hpp"
#include "abcpwn/commands/pwninit.hpp"
#include "abcpwn/commands/ret2dl.hpp"
#include "abcpwn/commands/rop.hpp"
#include "abcpwn/commands/safe_link.hpp"
#include "abcpwn/commands/search.hpp"
#include "abcpwn/commands/seccomp.hpp"
#include "abcpwn/commands/shellcode.hpp"
#include "abcpwn/commands/signal_cmd.hpp"
#include "abcpwn/commands/srop.hpp"
#include "abcpwn/commands/strings.hpp"
#include "abcpwn/commands/syms.hpp"
#include "abcpwn/commands/template_cmd.hpp"
#include "abcpwn/commands/vtable.hpp"
#include "abcpwn/commands/xor_cmd.hpp"

namespace {

struct DispatchEntry {
    std::unique_ptr<abcpwn::core::ICommand> cmd;
    CLI::App* sub{nullptr};
};

// Strip a leading "<cmd>: " or "<cmd> <action>: " that a command added
// to its own error message, so the single dispatcher prefix
// ("[-] <cmd>: ") is never doubled (DEF-1). Shared by the pretty and the
// JSON (DEF-4) error paths.
std::string strip_cmd_prefix(std::string_view cmd, std::string_view message) {
    if (!message.starts_with(cmd)) {
        return std::string(message);
    }
    const auto colon = message.find(": ", cmd.size());
    if (colon == std::string_view::npos) {
        return std::string(message);
    }
    // The text between <cmd> and ": " must be empty (exact "<cmd>: ") or a
    // single action word (" <action>"), so a real message that merely
    // starts with the command's name is never truncated.
    const std::string_view gap = message.substr(cmd.size(), colon - cmd.size());
    bool is_prefix = gap.empty();
    if (!is_prefix && gap.front() == ' ') {
        const std::string_view word = gap.substr(1);
        is_prefix = !word.empty() && word.find(' ') == std::string_view::npos;
    }
    return is_prefix ? std::string(message.substr(colon + 2)) : std::string(message);
}

// Detect "--format json" / "-f json" from raw argv. The Context (and
// thus ctx.format) is only built after a successful parse, so a parse
// FAILURE must consult argv directly to decide whether to render the
// error as JSON (DEF-4).
bool argv_requests_json(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        const std::string_view a = argv[i];
        if ((a == "--format" || a == "-f") && i + 1 < argc) {
            if (std::string_view(argv[i + 1]) == "json") {
                return true;
            }
        } else if (a == "--format=json" || a == "-fjson") {
            return true;
        }
    }
    return false;
}

// --log-file: write a single JSON record describing the run to the
// configured path (verification #20). The man page documents the flag
// as "a JSON log of the run", so we honor that literally rather than
// emitting spdlog text. Best-effort: a path that cannot be opened is
// skipped silently so logging never changes a command's exit status.
void write_run_log(const abcpwn::core::Context& ctx,
                   const std::string& command,
                   const std::string& command_line,
                   int exit_code,
                   bool ok,
                   const std::string& error_message,
                   std::chrono::nanoseconds duration) {
    if (!ctx.log_file || ctx.log_file->empty()) {
        return;
    }
    nlohmann::json j;
    j["abcpwn_version"] = abcpwn::core::semver_string;
    j["command"] = command;
    j["command_line"] = command_line;
    j["exit_code"] = exit_code;
    j["ok"] = ok;
    if (!error_message.empty()) {
        j["error"] = error_message;
    }
    j["duration_ms"] = std::chrono::duration<double, std::milli>(duration).count();
    std::ofstream out(*ctx.log_file, std::ios::trunc);
    if (out) {
        out << j.dump(2) << "\n";
    }
}

// STEP/18-shaped --version output. Combines the compact banner
// header (per STEP/02) with the build provenance block configured
// from cmake/version.hpp.in. The banner header is suppressed when
// include_banner=false (caller pre-checks --no-banner).
std::string build_version_block(bool include_banner) {
    namespace core = abcpwn::core;
    std::ostringstream os;
    if (include_banner) {
        os << abcpwn::output::compact_header() << "\n\n";
    }
    // The version_string here is PROJECT_VERSION ("0.1.0"). For
    // pre-release tags (e.g. v0.1.0-alpha.3) the full SemVer
    // string lives in core::semver_string which is configured
    // from the most-recent git tag at build time and includes
    // any -alpha.N / -beta.N / -rc.N suffix.
    os << "abcpwn v" << core::semver_string << " (commit " << core::git_commit << ", built "
       << core::build_date << ")\n";
    os << "  arch: " << core::arch_triple << "\n";
    os << "  compiler: " << core::cxx_compiler << "\n";
    os << "  features: keystone=" << (core::have_keystone ? "yes" : "no")
       << " network=" << (core::have_network ? "yes" : "no")
       << " unicorn=" << (core::have_unicorn ? "yes" : "no") << "\n";
    os << "  vcpkg-baseline: " << core::vcpkg_baseline << "\n";
    os << "  LIEF: " << core::lief_version << "\n";
    os << "  Capstone: " << core::capstone_version << "\n";
    os << "\nApache-2.0 licensed.\n";
    os << "https://github.com/manop55555/abcpwn\n";
    return os.str();
}

// Human-readable summary of the no-network policy. Printed by
// --about-network so CTF organizers and security auditors can
// confirm the invariant without grepping source. Mirrors the
// guarantees enumerated in docs/SECURITY-MODEL.md.
std::string build_about_network_text() {
    namespace core = abcpwn::core;
    std::ostringstream os;
    os << "abcpwn network policy\n";
    os << "=====================\n\n";
    os << "abcpwn makes no network calls by default. Only two\n";
    os << "subcommands ever touch the wire, and both refuse to run\n";
    os << "without the explicit --allow-network global flag:\n\n";
    os << "  libc download    fetch a libc archive from libc.rip\n";
    os << "  pwninit          fetch the matching dynamic linker\n\n";
    os << "Without --allow-network, those subcommands exit with code\n";
    os << "12 (NetworkDisabled) and print:\n";
    os << "  [-] network access disabled (use --allow-network to enable)\n\n";
    os << "All other subcommands operate offline against the local\n";
    os << "filesystem only. There is no telemetry, no analytics, no\n";
    os << "crash reporting, no auto-update, and no phone-home of any\n";
    os << "kind. CI enforces this via scripts/check-no-telemetry.sh\n";
    os << "and scripts/check-urls.sh.\n\n";
    os << "Defense-in-depth: setting ABCPWN_NO_NETWORK=1 in the\n";
    os << "environment forces network access off even when\n";
    os << "--allow-network is passed. Useful for locked-down CI or\n";
    os << "shared infrastructure.\n\n";
    os << "Build-time feature flags affecting network code:\n";
    os << "  network=" << (core::have_network ? "yes" : "no") << "\n";
    os << "(When network=no, the libc download and pwninit fetch\n";
    os << "code paths are compiled out entirely.)\n";
    return os.str();
}

template <class C>
void register_command(CLI::App& root, std::vector<DispatchEntry>& entries) {
    DispatchEntry e;
    e.cmd = std::make_unique<C>();
    e.sub = root.add_subcommand(std::string(e.cmd->name()), std::string(e.cmd->description()));
    e.cmd->setup(*e.sub);
    entries.push_back(std::move(e));
}

void register_all(CLI::App& root, std::vector<DispatchEntry>& entries) {
    using namespace abcpwn::commands;

    // Group 1: recon
    register_command<InfoCommand>(root, entries);
    register_command<SymsCommand>(root, entries);
    register_command<StringsCommand>(root, entries);
    register_command<SearchCommand>(root, entries);
    register_command<HashCommand>(root, entries);

    // Group 2: encoding
    register_command<PackCommand>(root, entries);
    register_command<UnpackCommand>(root, entries);
    register_command<HexCommand>(root, entries);
    register_command<UnhexCommand>(root, entries);
    register_command<B64Command>(root, entries);
    register_command<XorCommand>(root, entries);
    register_command<ErrnoCommand>(root, entries);
    register_command<SignalCommand>(root, entries);
    register_command<ConstgrepCommand>(root, entries);

    // Group 3 + 4: assembly + pattern
    register_command<AsmCommand>(root, entries);
    register_command<DisasmCommand>(root, entries);
    register_command<PhdCommand>(root, entries);
    register_command<CyclicCommand>(root, entries);

    // Group 5: ROP
    register_command<GadgetCommand>(root, entries);
    register_command<RopCommand>(root, entries);
    register_command<OneGadgetCommand>(root, entries);

    // Group 6: specialized
    register_command<srop::SropCommand>(root, entries);
    register_command<ret2dl::Ret2dlCommand>(root, entries);
    register_command<dynelf::DynelfCommand>(root, entries);
    register_command<aslr_bypass::AslrBypassCommand>(root, entries);

    // Group 7 + 8: shellcode + fmt
    register_command<shellcode::ShellcodeCommand>(root, entries);
    register_command<fmt::FmtCommand>(root, entries);

    // Group 9: GOT
    register_command<got::GotCommand>(root, entries);

    // Group 10: heap
    register_command<heap::HeapCommand>(root, entries);
    register_command<safe_link::SafeLinkCommand>(root, entries);

    // Group 11: FILE / C++
    register_command<iofile::IofileCommand>(root, entries);
    register_command<vtable::VtableCommand>(root, entries);

    // Group 12: sandbox + libc
    register_command<seccomp::SeccompCommand>(root, entries);
    register_command<libc::LibcCommand>(root, entries);

    // Group 13: workflow
    register_command<pwninit::PwninitCommand>(root, entries);
    register_command<pwn::PwnCommand>(root, entries);
    register_command<tmpl::TemplateCommand>(root, entries);
    register_command<diffpatch::DiffCommand>(root, entries);
    register_command<diffpatch::PatchCommand>(root, entries);
}

} // namespace

int main(int argc, char** argv) {
    using namespace abcpwn;

    CLI::App app{"abcpwn - binary exploitation toolkit"};
    // --version is handled manually after parse so --no-banner
    // can suppress the compact_header in the version block. The
    // default CLI11 set_version_flag fires its callback inline
    // during parsing and has no way to consult other flags.
    bool show_version{false};
    app.add_flag("--version", show_version, "Print version and exit");
    app.require_subcommand(0, 1);

    // --about-network prints the no-network policy and exits.
    // Handled via a flag-with-callback so it short-circuits before
    // subcommand dispatch, matching the --version pattern.
    bool show_about_network{false};
    app.add_flag("--about-network",
                 show_about_network,
                 "Print the network policy and exit (no network calls).");

    // Global flags. After parse they are folded into a Context that
    // every ICommand::run sees.
    std::string format_str{"pretty"};
    std::string color_str{"auto"};
    int verbose_count{0};
    bool quiet{false};
    bool no_banner{false};
    bool show_banner{false};
    bool no_color{false};
    bool allow_network{false};
    std::string config_path{};

    app.add_option("-f,--format", format_str, "pretty (default) | json");
    app.add_option("--color", color_str, "auto (default) | always | never");
    app.add_flag("--no-color", no_color, "Disable color output (alias for --color never)");
    app.add_flag("-v,--verbose", verbose_count, "Increase verbosity (-vv = trace)");
    app.add_flag("-q,--quiet", quiet, "Suppress info-level output");
    app.add_flag("--no-banner", no_banner, "Suppress the banner");
    app.add_flag("--banner", show_banner, "Print the banner and exit");
    app.add_flag(
        "--allow-network", allow_network, "Permit network access (libc download, pwninit fetch)");
    app.add_option("--config", config_path, "Path to a TOML config file");
    std::string log_file{};
    app.add_option("--log-file", log_file, "Write a JSON log of the run to PATH");

    std::vector<DispatchEntry> entries;
    register_all(app, entries);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        // --help / --version / "--" surface as ParseError with exit code
        // 0; let CLI11 print them to stdout and exit cleanly.
        if (e.get_exit_code() == 0) {
            return app.exit(e);
        }
        // A real parse error. CLI11's own exit codes (104 RequiredError,
        // 106 ExtrasError, 109 RequiresError, ...) are leaked straight
        // through by app.exit(); operators see "exit 109" with no entry
        // in docs/ERROR_CODES.md. Funnel every parse-time error through
        // exit 2 (UsageError) so the documented exit table is the single
        // source of truth. In JSON mode, render the failure as a JSON
        // envelope on stdout (DEF-4) -- the Context is not built yet, so
        // detect the format from argv.
        if (argv_requests_json(argc, argv)) {
            core::Context json_ctx;
            json_ctx.format = core::OutputFormat::Json;
            output::JsonWriter(json_ctx).write_error(std::cout,
                                                     "",
                                                     static_cast<int>(core::ErrorCode::UsageError),
                                                     "UsageError",
                                                     e.what());
            return static_cast<int>(core::ErrorCode::UsageError);
        }
        app.exit(e); // CLI11 writes its own diagnostic to stderr
        return static_cast<int>(core::ErrorCode::UsageError);
    }

    // Validate the global enum flags (DEF-6): silently falling back to
    // pretty/auto previously hid typos like `--format JSON` (case) or
    // `--color bogus`. These are pre-dispatch config errors, so they go
    // to stderr regardless of the (possibly invalid) format request.
    if (auto e = core::validate_choice(
            "invalid format", format_str, {"pretty", "json"}, core::ErrorCode::InvalidInput)) {
        std::cerr << "[-] " << e->message << '\n';
        return e->exit_code();
    }
    if (auto e = core::validate_choice("invalid color",
                                       color_str,
                                       {"auto", "always", "never"},
                                       core::ErrorCode::InvalidInput)) {
        std::cerr << "[-] " << e->message << '\n';
        return e->exit_code();
    }

    // Build the Context from parsed globals.
    core::Context ctx;
    ctx.format = (format_str == "json") ? core::OutputFormat::Json : core::OutputFormat::Pretty;
    if (no_color || color_str == "never")
        ctx.color = core::ColorMode::Never;
    else if (color_str == "always")
        ctx.color = core::ColorMode::Always;
    else
        ctx.color = core::ColorMode::Auto;
    ctx.verbosity = verbose_count - (quiet ? 1 : 0);
    ctx.no_banner = no_banner;
    ctx.allow_network = allow_network;
    if (!log_file.empty()) {
        ctx.log_file = log_file;
    }

    // QA round 1 OBSERVATION: a `network=no` build silently accepts
    // --allow-network at parse time and then surfaces FeatureDisabled
    // later when the network-using subcommand fires. Warn at parse
    // time so the operator sees the mismatch immediately and does not
    // build automation against a flag that has no effect on this
    // binary. The warning goes to stderr; we do NOT abort the command
    // because non-network subcommands work fine and the user might
    // have inherited the flag from a shell alias.
    if (allow_network && !core::have_network) {
        std::cerr << "[!] --allow-network passed but this build was produced without "
                  << "ABCPWN_WITH_NETWORK=ON; the libc download and pwninit fetch paths "
                  << "are compiled out and the flag has no effect.\n";
    }

    // Defense-in-depth: ABCPWN_NO_NETWORK=1 in the environment forces
    // network access off even when --allow-network is passed. Lets
    // locked-down CI and shared infrastructure prevent operators from
    // accidentally enabling the two network-using subcommands.
    if (const char* no_net = std::getenv("ABCPWN_NO_NETWORK");
        no_net != nullptr && std::string_view{no_net} == "1") {
        ctx.allow_network = false;
    }

    // ABCPWN_MAX_FILE_SIZE overrides the default 2 GB input-file
    // size cap. Accepts a decimal number of bytes. Invalid values
    // leave the default in place; the limit is a guard against
    // OOM from malformed binaries, so a parse failure shouldn't
    // disable it.
    if (const char* mfs = std::getenv("ABCPWN_MAX_FILE_SIZE"); mfs != nullptr && *mfs != '\0') {
        char* endp = nullptr;
        const auto v = std::strtoull(mfs, &endp, 10);
        if (endp != mfs && *endp == '\0' && v > 0) {
            ctx.limits.max_file_bytes = static_cast<std::size_t>(v);
        }
    }
    if (!config_path.empty()) {
        auto cfg = core::config::load(config_path);
        if (!cfg) {
            std::cerr << "[-] config: " << cfg.error().message << '\n';
            return cfg.error().exit_code();
        }
        core::config::apply_to_context(*cfg, ctx);
    }

    output::setup_logging(ctx);
    core::signal::install_handlers();

    // --banner: print and exit, regardless of subcommand. The
    // banner is decoration; emit on stderr so stdout stays clean
    // for any caller that redirects it.
    if (show_banner) {
        const bool color = output::PrettyPrinter::should_color(ctx, std::cerr);
        output::print_banner(std::cerr, color);
        return 0;
    }

    // --version: print the STEP/18 version block and exit. The
    // compact_header at the top of the block is omitted when
    // --no-banner is set so callers that pipe `--version` get
    // only the structured fields.
    if (show_version) {
        std::cout << build_version_block(/*include_banner=*/!ctx.no_banner);
        return 0;
    }

    // --about-network: print the policy and exit. Done after the
    // Context is built so the printed feature flags reflect the
    // running binary, not just compile-time defaults.
    if (show_about_network) {
        std::cout << build_about_network_text();
        return 0;
    }

    // Locate the selected subcommand by parsed() introspection.
    const DispatchEntry* selected = nullptr;
    for (const auto& e : entries) {
        if (e.sub->parsed()) {
            selected = &e;
            break;
        }
    }

    if (selected == nullptr) {
        // No subcommand chosen: banner + help. Banner emits on
        // stderr (decoration, never on the data channel). Help
        // text stays on stdout per Unix convention for --help.
        if (!ctx.no_banner && !ctx.quiet() && ctx.format != core::OutputFormat::Json) {
            const bool color = output::PrettyPrinter::should_color(ctx, std::cerr);
            output::print_banner(std::cerr, color);
            std::cerr << '\n';
        }
        std::cout << app.help();
        return 0;
    }

    const auto start_at = std::chrono::steady_clock::now();
    auto result = selected->cmd->run(ctx);
    const auto end_at = std::chrono::steady_clock::now();
    const auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end_at - start_at);

    // Joined argv, reused by the --log-file run-record and (in JSON
    // mode) the args.command_line echo so a downstream jq pipeline can
    // correlate an output blob back to the invocation that produced it.
    std::string command_line;
    for (int i = 0; i < argc; ++i) {
        if (i != 0) {
            command_line.push_back(' ');
        }
        command_line.append(argv[i]);
    }
    const std::string cmd_name{selected->cmd->name()};

    if (!result) {
        const auto& e = result.error();
        const std::string msg = strip_cmd_prefix(cmd_name, e.message);
        write_run_log(ctx, cmd_name, command_line, e.exit_code(), false, msg, elapsed);
        if (ctx.format == core::OutputFormat::Json) {
            // DEF-4: emit a JSON error envelope on stdout so pipelines can
            // parse failures rather than scrape human-readable stderr.
            std::map<std::string, std::variant<std::string, std::int64_t, bool>> json_args;
            json_args.emplace("command_line", command_line);
            output::JsonWriter(ctx).write_error(
                std::cout, cmd_name, e.exit_code(), core::error_code_name(e.code), msg, json_args);
        } else {
            std::cerr << "[-] " << cmd_name << ": " << msg << '\n';
        }
        return e.exit_code();
    }

    if (!result->duration) {
        result->duration = elapsed;
    }
    write_run_log(ctx,
                  cmd_name,
                  command_line,
                  result->exit_code,
                  true,
                  "",
                  result->duration.value_or(elapsed));

    // -v/-vv: setup_logging raised the logger level from ctx.verbosity,
    // but nothing was emitted at debug/trace, so increased verbosity had
    // no observable effect (DEF-18). Log a dispatch line at debug; hidden
    // at the default info level and in JSON mode (no console sink).
    {
        std::ostringstream dbg;
        dbg << "command '" << cmd_name << "' completed in "
            << std::chrono::duration<double, std::milli>(result->duration.value_or(elapsed)).count()
            << " ms (exit " << result->exit_code << ")";
        output::log_debug(dbg.str());
    }

    if (ctx.format == core::OutputFormat::Json) {
        std::map<std::string, std::variant<std::string, std::int64_t, bool>> json_args;
        json_args.emplace("command_line", command_line);
        output::JsonWriter writer(ctx);
        writer.write(std::cout, cmd_name, *result, json_args);
    } else {
        output::PrettyPrinter pp(ctx);
        // Compact header and timing footer are decoration -- they go to
        // stderr so a caller can redirect stdout (raw bytes, JSON for jq,
        // hex dumps) without seeing them. Suppressed for raw_payload
        // results (pristine binary output) and under -q (DEF-18).
        if (!ctx.no_banner && !ctx.quiet() && !result->raw_payload) {
            pp.print_command_header(std::cerr);
        }
        pp.print_command_result(std::cout, *result);
        if (!ctx.quiet()) {
            pp.print_timing(std::cerr, *result);
        }
    }

    return result->exit_code;
}
