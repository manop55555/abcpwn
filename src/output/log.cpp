// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/output/log.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <spdlog/logger.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace abcpwn::output {

namespace {

constexpr const char* kLoggerName = "abcpwn";

std::mutex g_mu;
std::shared_ptr<spdlog::logger> g_logger;
std::string g_log_path;

spdlog::level::level_enum level_from_verbosity(int v) {
    if (v <= -2)
        return spdlog::level::err;
    if (v == -1)
        return spdlog::level::warn;
    if (v == 0)
        return spdlog::level::info;
    if (v == 1)
        return spdlog::level::debug;
    return spdlog::level::trace; // 2+
}

} // namespace

void setup_logging(const core::Context& ctx) {
    std::scoped_lock lk(g_mu);

    std::vector<spdlog::sink_ptr> sinks;
    if (ctx.format != core::OutputFormat::Json) {
        auto console = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        sinks.push_back(std::move(console));
    }
    // --log-file is a JSON run-record written directly by the dispatcher
    // (see write_run_log in main.cpp), not an spdlog text sink. Record
    // the configured path for diagnostics, but do not attach a file sink
    // here -- a mixed spdlog-text + JSON file would not parse as JSON.
    if (ctx.log_file && !ctx.log_file->empty()) {
        g_log_path = *ctx.log_file;
    } else {
        g_log_path.clear();
    }

    if (sinks.empty()) {
        // Always provide at least one sink so callers never see null.
        sinks.push_back(std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
    }

    auto logger = std::make_shared<spdlog::logger>(kLoggerName, sinks.begin(), sinks.end());
    logger->set_level(level_from_verbosity(ctx.verbosity));
    logger->set_pattern("[%H:%M:%S.%e] [%^%l%$] %v");
    logger->flush_on(spdlog::level::warn);

    spdlog::set_default_logger(logger);
    g_logger = std::move(logger);
}

std::shared_ptr<spdlog::logger> get_logger() {
    std::scoped_lock lk(g_mu);
    if (!g_logger) {
        auto console = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        g_logger = std::make_shared<spdlog::logger>(kLoggerName, spdlog::sinks_init_list{console});
        g_logger->set_level(spdlog::level::info);
    }
    return g_logger;
}

const std::string& last_log_path_for_testing() {
    std::scoped_lock lk(g_mu);
    return g_log_path;
}

} // namespace abcpwn::output
