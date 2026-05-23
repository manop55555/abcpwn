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
#include "abcpwn/core/version.hpp"
#include "abcpwn/output/banner.hpp"
#include "abcpwn/output/json_writer.hpp"
#include "abcpwn/output/log.hpp"
#include "abcpwn/output/pretty.hpp"

// Every command surface.
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <CLI/CLI.hpp>

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

// STEP/18-shaped --version output. Combines the compact banner
// header (per STEP/02) with the build provenance block configured
// from cmake/version.hpp.in. Returned as a single string so CLI11
// can hand it to the user via set_version_flag's callback.
std::string build_version_block() {
    namespace core = abcpwn::core;
    std::ostringstream os;
    os << abcpwn::output::compact_header() << "\n\n";
    os << "abcpwn v" << core::version_string << " (commit " << core::git_commit << ", built "
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
    app.set_version_flag("--version", &build_version_block);
    app.require_subcommand(0, 1);

    // Global flags. After parse they are folded into a Context that
    // every ICommand::run sees.
    std::string format_str{"pretty"};
    std::string color_str{"auto"};
    int verbose_count{0};
    bool quiet{false};
    bool no_banner{false};
    bool show_banner{false};
    bool allow_network{false};
    std::string config_path{};
    std::string log_file_path{};

    app.add_option("--format", format_str, "pretty (default) | json");
    app.add_option("--color", color_str, "auto (default) | always | never");
    app.add_flag("-v,--verbose", verbose_count, "Increase verbosity (-vv = trace)");
    app.add_flag("-q,--quiet", quiet, "Suppress info-level output");
    app.add_flag("--no-banner", no_banner, "Suppress the banner");
    app.add_flag("--banner", show_banner, "Print the banner and exit");
    app.add_flag(
        "--allow-network", allow_network, "Permit network access (libc download, pwninit fetch)");
    app.add_option("--config", config_path, "Path to a TOML config file");
    app.add_option("--log-file",
                   log_file_path,
                   "Write logs to this path (in addition to stderr in pretty mode)");

    std::vector<DispatchEntry> entries;
    register_all(app, entries);

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }

    // Build the Context from parsed globals.
    core::Context ctx;
    ctx.format = (format_str == "json") ? core::OutputFormat::Json : core::OutputFormat::Pretty;
    if (color_str == "always")
        ctx.color = core::ColorMode::Always;
    else if (color_str == "never")
        ctx.color = core::ColorMode::Never;
    else
        ctx.color = core::ColorMode::Auto;
    ctx.verbosity = verbose_count - (quiet ? 1 : 0);
    ctx.no_banner = no_banner;
    ctx.allow_network = allow_network;
    if (!log_file_path.empty()) {
        ctx.log_file = log_file_path;
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

    // --banner: print and exit, regardless of subcommand.
    if (show_banner) {
        const bool color = output::PrettyPrinter::should_color(ctx, std::cout);
        output::print_banner(std::cout, color);
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
        // No subcommand chosen: banner + help (unless --no-banner or
        // JSON mode -- JSON callers don't want banner bytes corrupting
        // their parse).
        if (!ctx.no_banner && ctx.format != core::OutputFormat::Json) {
            const bool color = output::PrettyPrinter::should_color(ctx, std::cout);
            output::print_banner(std::cout, color);
            std::cout << '\n';
        }
        std::cout << app.help();
        return 0;
    }

    const auto start_at = std::chrono::steady_clock::now();
    auto result = selected->cmd->run(ctx);
    const auto end_at = std::chrono::steady_clock::now();

    if (!result) {
        std::cerr << "[-] " << selected->cmd->name() << ": " << result.error().message << '\n';
        return result.error().exit_code();
    }

    if (!result->duration) {
        result->duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end_at - start_at);
    }

    if (ctx.format == core::OutputFormat::Json) {
        output::JsonWriter writer(ctx);
        writer.write(std::cout, selected->cmd->name(), *result);
    } else {
        output::PrettyPrinter pp(ctx);
        if (!ctx.no_banner) {
            pp.print_command_header(std::cout);
        }
        pp.print_command_result(std::cout, *result);
    }

    return result->exit_code;
}
