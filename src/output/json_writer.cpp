// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 manop55555

#include "abcpwn/output/json_writer.hpp"

#include <chrono>
#include <ostream>
#include <variant>

#include <nlohmann/json.hpp>

#include "abcpwn/core/version.hpp"

namespace abcpwn::output {

using json = nlohmann::json;

std::string_view severity_json_name(core::Severity s) noexcept {
    switch (s) {
    case core::Severity::Info:
        return "info";
    case core::Severity::Low:
        return "low";
    case core::Severity::Medium:
        return "medium";
    case core::Severity::High:
        return "high";
    case core::Severity::Critical:
        return "critical";
    }
    return "info";
}

JsonWriter::JsonWriter(const core::Context& ctx) : ctx_(ctx) {}

namespace {

json finding_to_json(const core::Finding& f) {
    json j;
    j["title"] = f.title;
    j["detail"] = f.detail;
    j["severity"] = std::string(severity_json_name(f.severity));
    if (f.offset) {
        j["offset"] = *f.offset;
    }
    if (f.file) {
        j["file"] = *f.file;
    }
    if (!f.extra.empty()) {
        json e = json::object();
        for (const auto& [k, v] : f.extra) {
            std::visit([&](const auto& val) { e[k] = val; }, v);
        }
        j["extra"] = std::move(e);
    }
    return j;
}

json section_to_json(const core::Section& s) {
    json j;
    j["title"] = s.title;
    json arr = json::array();
    for (const auto& f : s.findings) {
        arr.push_back(finding_to_json(f));
    }
    j["findings"] = std::move(arr);
    return j;
}

void count_severity(const core::Section& s, int& info, int& low, int& med, int& high, int& crit) {
    for (const auto& f : s.findings) {
        switch (f.severity) {
        case core::Severity::Info:
            ++info;
            break;
        case core::Severity::Low:
            ++low;
            break;
        case core::Severity::Medium:
            ++med;
            break;
        case core::Severity::High:
            ++high;
            break;
        case core::Severity::Critical:
            ++crit;
            break;
        }
    }
}

} // namespace

void JsonWriter::write(
    std::ostream& os,
    std::string_view command,
    const core::CommandResult& res,
    const std::map<std::string, std::variant<std::string, std::int64_t, bool>>& args) const {
    (void) ctx_;

    json envelope;
    envelope["abcpwn_version"] = std::string(core::version_string);
    envelope["schema_version"] = kJsonSchemaVersion;
    envelope["command"] = std::string(command);

    json args_json = json::object();
    for (const auto& [k, v] : args) {
        std::visit([&](const auto& val) { args_json[k] = val; }, v);
    }
    envelope["args"] = std::move(args_json);

    if (res.duration) {
        envelope["duration_ms"] =
            std::chrono::duration_cast<std::chrono::milliseconds>(*res.duration).count();
    } else {
        envelope["duration_ms"] = 0;
    }

    json sections_arr = json::array();
    json findings_arr = json::array();
    int info = 0, low = 0, med = 0, high = 0, crit = 0;
    for (const auto& s : res.sections) {
        sections_arr.push_back(section_to_json(s));
        for (const auto& f : s.findings) {
            findings_arr.push_back(finding_to_json(f));
        }
        count_severity(s, info, low, med, high, crit);
    }
    envelope["result"] = json{{"sections", std::move(sections_arr)}};
    envelope["findings"] = std::move(findings_arr);
    envelope["summary"] = json{
        {"info", info},
        {"low", low},
        {"medium", med},
        {"high", high},
        {"critical", crit},
    };
    if (res.summary) {
        envelope["result"]["summary_text"] = *res.summary;
    }
    if (!res.raw_lines.empty()) {
        envelope["result"]["lines"] = res.raw_lines;
    }
    envelope["result"]["exit_code"] = res.exit_code;

    os << envelope.dump(2) << '\n';
}

} // namespace abcpwn::output
