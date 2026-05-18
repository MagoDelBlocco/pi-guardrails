#include <napi.h>
#include <string>
#include <vector>
#include <filesystem>
#include "rules/rule.h"

namespace {

// Convert a Severity enum to a JSON-friendly string.
static std::string severityToString(Severity s) {
    switch (s) {
        case Severity::CRITICAL: return "critical";
        case Severity::WARNING:  return "warning";
    }
    return "unknown";
}

// Serialize a single Violation to JSON.
static std::string violationToJson(const Violation& v) {
    std::string escaped;
    escaped.reserve(v.message.size() + 16);
    for (char c : v.message) {
        if (c == '"')  escaped += "\\\"";
        else if (c == '\\') escaped += "\\\\";
        else if (c == '\n') escaped += "\\n";
        else if (c == '\r') escaped += "\\r";
        else if (c == '\t') escaped += "\\t";
        else escaped += c;
    }
    return "{\"category\":\"" + v.category +
           "\",\"severity\":\"" + severityToString(v.severity) +
           "\",\"message\":\"" + escaped + "\"}";
}

// Serialize a vector of Violations to a JSON array string.
static std::string violationsToJson(const std::vector<Violation>& vs) {
    if (vs.empty()) return "null";
    std::string result = "[";
    for (size_t i = 0; i < vs.size(); ++i) {
        if (i > 0) result += ",";
        result += violationToJson(vs[i]);
    }
    result += "]";
    return result;
}

} // anonymous namespace

/*
 * init(extensionRoot, piConfigDir, tirithBinary, homeDir)
 *
 * Called once at extension startup to cache protected paths.
 */
Napi::Value InitAddon(const Napi::CallbackInfo& info) {
    std::string extensionRoot = info[0].As<Napi::String>().Utf8Value();
    std::string piConfigDir   = info[1].As<Napi::String>().Utf8Value();
    std::string piInstallDir  = info[2].As<Napi::String>().Utf8Value();
    std::string tirithBinary  = info[3].As<Napi::String>().Utf8Value();
    initSelfDisabling(extensionRoot, piConfigDir, piInstallDir, tirithBinary);
    return info.Env().Undefined();
}

/*
 * checkPath(cwd, targetPath, operation, homeDir) -> string
 *
 * operation: "read" | "write" | "edit"
 * Checks: cwd-escape (Warning) + self-disabling (Critical).
 */
Napi::String CheckPath(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string cwd        = info[0].As<Napi::String>().Utf8Value();
    std::string targetPath = info[1].As<Napi::String>().Utf8Value();
    std::string operation  = info[2].As<Napi::String>().Utf8Value();
    std::string homeDir    = info[3].As<Napi::String>().Utf8Value();

    std::vector<Violation> all;

    // ── Cwd-escape check ──────────────────────────────────────
    // Only flag relative paths that use .. to traverse outside cwd.
    // Absolute paths are explicit — caught by sensitive-path / self-disabling rules.
    {
        std::filesystem::path rawTarget(targetPath);
        if (!rawTarget.is_absolute()) {
            std::filesystem::path cwdPath = std::filesystem::weakly_canonical(cwd);
            std::filesystem::path target  = std::filesystem::weakly_canonical(
                std::filesystem::path(cwd) / targetPath
            );
            std::string targetStr = target.string();
            std::string cwdStr    = cwdPath.string();
            if (cwdStr.back() != '/') cwdStr += '/';

            if (targetStr != cwdPath.string() && targetStr.rfind(cwdStr, 0) != 0) {
                all.push_back({"path-escape", Severity::WARNING,
                    "Path escape detected: '" + targetStr + "' is outside cwd '" + cwdPath.string() + "'"
                });
            }
        }
    }

    // ── Self-disabling check ──────────────────────────────────
    {
        auto selfViolations = checkSelfDisablingPath(targetPath, operation, homeDir);
        all.insert(all.end(), selfViolations.begin(), selfViolations.end());
    }

    return Napi::String::New(env, violationsToJson(all));
}

/*
 * checkCommand(command, homeDir, cwd) -> string
 *
 * Runs the command through all bash rule checks:
 *   shell-composition, process-control, file-destruction,
 *   package-manager, sensitive-paths, self-disabling.
 */
Napi::String CheckCommand(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string command = info[0].As<Napi::String>().Utf8Value();
    std::string homeDir = info[1].As<Napi::String>().Utf8Value();
    std::string cwd     = info[2].As<Napi::String>().Utf8Value();

    std::vector<Violation> all;

    // Split into pipeline segments so compounds like
    // `do_stuff && rm /path/to/extension/config` block on segment 2.
    auto segments = splitPipeline(command);

    for (const auto& seg : segments) {
        auto shellViolations = checkShellComposition(seg);
        all.insert(all.end(), shellViolations.begin(), shellViolations.end());

        auto processViolations = checkProcessControl(seg);
        all.insert(all.end(), processViolations.begin(), processViolations.end());

        auto destroyViolations = checkFileDestruction(seg);
        all.insert(all.end(), destroyViolations.begin(), destroyViolations.end());

        auto pkgViolations = checkPackageManager(seg);
        all.insert(all.end(), pkgViolations.begin(), pkgViolations.end());

        auto sensitiveViolations = checkSensitivePaths(seg, homeDir, cwd);
        all.insert(all.end(), sensitiveViolations.begin(), sensitiveViolations.end());

        auto selfViolations = checkSelfDisablingCommand(seg, homeDir, cwd);
        all.insert(all.end(), selfViolations.begin(), selfViolations.end());
    }

    return Napi::String::New(env, violationsToJson(all));
}

/*
 * checkShellInitContent(targetPath, newContent, homeDir, cwd) -> string
 *
 * Checks if writing newContent to a shell init file would remove
 * guardrail initialization lines.
 */
Napi::String CheckShellInitContent(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    std::string targetPath = info[0].As<Napi::String>().Utf8Value();
    std::string newContent = info[1].As<Napi::String>().Utf8Value();
    std::string homeDir    = info[2].As<Napi::String>().Utf8Value();
    std::string cwd        = info[3].As<Napi::String>().Utf8Value();

    auto violations = checkShellInitContent(targetPath, newContent, homeDir, cwd);
    return Napi::String::New(env, violationsToJson(violations));
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    exports.Set("init",                  Napi::Function::New(env, InitAddon));
    exports.Set("checkPath",             Napi::Function::New(env, CheckPath));
    exports.Set("checkCommand",          Napi::Function::New(env, CheckCommand));
    exports.Set("checkShellInitContent", Napi::Function::New(env, CheckShellInitContent));
    return exports;
}

NODE_API_MODULE(addon, Init)
