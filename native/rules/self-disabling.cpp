#include "rule.h"
#include <regex>
#include <algorithm>
#include <cctype>

/*
 * Self-disabling protection (Warning, user prompt).
 *
 * Prevents the agent from modifying, removing, or bypassing anything
 * that controls the guardrail extension, pi itself, or tirith.
 *
 * Protected paths are resolved at init time and cached.
 * Any write, edit, rm, mv, cp, chmod, chown, chattr, ln, truncate,
 * or dd targeting these paths triggers a user confirmation prompt.
 */

namespace {

// Cached set of protected paths (canonical).
static std::set<std::string> protectedPaths;

// Cache of protected path prefixes (for rm -rf parent detection).
static std::vector<std::string> protectedPrefixes;

// Cached extensions directory (parent of extensionRoot) for same-extension filtering.
static std::string extensionsDir;

static bool isProtected(const std::string& resolvedPath) {
    // Exact match.
    if (protectedPaths.count(resolvedPath)) return true;
    // Check if resolvedPath is UNDER any protected path (e.g., ~/.pi/agent/foo/bar).
    for (const auto& pp : protectedPrefixes) {
        std::string ppSlash = pp;
        if (ppSlash.back() != '/') ppSlash += '/';
        if (resolvedPath.size() > ppSlash.size() &&
            resolvedPath.compare(0, ppSlash.size(), ppSlash) == 0) {
            return true;
        }
    }
    // Check if any protected path is under this path (parent-directory write like rm -rf).
    for (const auto& prefix : protectedPrefixes) {
        if (resolvedPath.size() < prefix.size() &&
            prefix.compare(0, resolvedPath.size(), resolvedPath) == 0) {
            return true;
        }
    }
    return false;
}

// Check if cwd and targetPath are in the same extension directory.
// Returns true if both are under the same subdirectory of extensionsDir.
static bool isSameExtension(const std::string& cwd, const std::string& targetPath) {
    if (extensionsDir.empty()) return false;
    std::string extSlash = extensionsDir;
    if (extSlash.back() != '/') extSlash += '/';

    // Both must be under extensionsDir.
    if (cwd.compare(0, extSlash.size(), extSlash) != 0) return false;
    if (targetPath.compare(0, extSlash.size(), extSlash) != 0) return false;

    // Extract the first path component after extensionsDir for each.
    std::filesystem::path cwdPath(cwd);
    std::filesystem::path targetPathFs(targetPath);
    std::filesystem::path extPath(extensionsDir);

    auto cwdRel = std::filesystem::relative(cwdPath, extPath);
    auto targetRel = std::filesystem::relative(targetPathFs, extPath);

    // Get the first component (the extension directory name).
    auto cwdFirst = cwdRel.begin();
    auto targetFirst = targetRel.begin();
    if (cwdFirst != cwdRel.end() && targetFirst != targetRel.end()) {
        return cwdFirst->string() == targetFirst->string();
    }
    return false;
}

// Resolve a path arg from a bash command: dequote → expandVars → resolveTilde → canonicalize.
// weakly_canonical can throw on permission-denied paths.
static std::string resolveBashPath(const std::string& rawArg,
                                    const std::string& homeDir,
                                    const std::string& cwd) {
    std::string expanded = expandVars(rawArg, homeDir, cwd);
    expanded = resolveTilde(expanded, homeDir);
    try {
        if (std::filesystem::path(expanded).is_absolute()) {
            return std::filesystem::weakly_canonical(expanded).string();
        }
        return std::filesystem::weakly_canonical(
            std::filesystem::path(cwd) / expanded
        ).string();
    } catch (const std::filesystem::filesystem_error&) {
        return expanded;
    }
}

} // anonymous namespace

void initSelfDisabling(const std::string& extensionRoot,
                        const std::string& piConfigDir,
                        const std::string& piInstallDir,
                        const std::string& tirithBinary) {
    protectedPaths.clear();
    protectedPrefixes.clear();

    // Cache the extensions directory (parent of extensionRoot) for same-extension filtering.
    std::filesystem::path extRootPath(extensionRoot);
    extensionsDir = extRootPath.parent_path().string();

    auto add = [](const std::string& p) {
        if (p.empty()) return;
        std::filesystem::path resolved;
        try {
            resolved = std::filesystem::weakly_canonical(p);
        } catch (const std::filesystem::filesystem_error&) {
            resolved = std::filesystem::path(p);
        }
        std::string s = resolved.string();
        protectedPaths.insert(s);
    };

    // Extension binary (the .node file).
    add(extensionRoot + "/native/build/Release/addon.node");

    // Extension source files (index.ts, binding.gyp, all .cpp/.h).
    add(extensionRoot + "/index.ts");
    add(extensionRoot + "/native/binding.gyp");
    add(extensionRoot + "/native/addon.cpp");
    add(extensionRoot + "/native/rules");

    // Entire ~/.pi/ directory and everything under it.
    // This covers: agent (extensions, sessions, skills), themes, etc.
    std::filesystem::path piConfigDirPath(piConfigDir);
    std::string piDir = piConfigDirPath.parent_path().string();
    add(piDir);

    // Tirith binary.
    add(tirithBinary);

    // Pi installation directory.
    add(piInstallDir);

    // Build prefix list for parent-directory detection.
    for (const auto& p : protectedPaths) {
        protectedPrefixes.push_back(p);
    }
}

// ── Path-based tool check (write / edit) ──────────────────────

std::vector<Violation> checkSelfDisablingPath(const std::string& targetPath,
                                               const std::string& operation,
                                               const std::string& homeDir,
                                               const std::string& cwd) {
    std::vector<Violation> violations;

    // Only block writes and edits, not reads.
    if (operation != "write" && operation != "edit") return violations;

    // Resolve the target path: expandVars → resolveTilde → canonicalize.
    // weakly_canonical can throw on permission-denied paths.
    std::string expanded = expandVars(targetPath, homeDir, "");
    expanded = resolveTilde(expanded, homeDir);
    std::filesystem::path resolved;
    try {
        resolved = std::filesystem::weakly_canonical(expanded);
    } catch (const std::filesystem::filesystem_error&) {
        resolved = std::filesystem::path(expanded);
    }
    std::string resolvedStr = resolved.string();

    if (isProtected(resolvedStr)) {
        // Suppress if cwd and target are in the same extension directory.
        if (isSameExtension(cwd, resolvedStr)) return violations;

        violations.push_back({"self-disabling", Severity::WARNING,
            "Blocked " + operation + " to protected path: " + resolvedStr});
    }

    return violations;
}

// ── Bash command check ────────────────────────────────────────

std::vector<Violation> checkSelfDisablingCommand(const std::string& command,
                                                   const std::string& homeDir,
                                                   const std::string& cwd) {
    std::vector<Violation> violations;

    // Commands that target files: rm, mv, cp, chmod, chown, chattr, ln, truncate
    static const std::regex file_cmd_re("\\b(rm|mv|cp|chmod|chown|chattr|ln|truncate)\\b");
    static const std::regex dd_of_re("\\bdd\\b.*\\bof=(\\S+)");

    // ── Direct file commands ──────────────────────────────────
    {
        std::smatch m;
        if (std::regex_search(command, m, file_cmd_re)) {
            std::string cmdName = m[1].str();
            auto fileArgs = extractFileArgs(command);

            for (const auto& arg : fileArgs) {
                std::string resolvedStr = resolveBashPath(arg, homeDir, cwd);

                if (isProtected(resolvedStr)) {
                    // Suppress if cwd and target are in the same extension directory.
                    if (isSameExtension(cwd, resolvedStr)) continue;
                    violations.push_back({"self-disabling", Severity::WARNING,
                        "Blocked " + cmdName + " on protected path: " + resolvedStr});
                }
            }
        }
    }

    // ── dd of= ────────────────────────────────────────────────
    {
        std::smatch m;
        if (std::regex_search(command, m, dd_of_re)) {
            std::string target = m[1].str();
            std::string resolvedStr = resolveBashPath(target, homeDir, cwd);

            if (isProtected(resolvedStr) && !isSameExtension(cwd, resolvedStr)) {
                violations.push_back({"self-disabling", Severity::WARNING,
                    "Blocked dd to protected path: " + resolvedStr});
            }
        }
    }

    // ── Redirects to protected paths (>, >>) ──────────────────
    {
        auto targets = extractRedirectTargets(command);
        for (const auto& target : targets) {
            std::string resolvedStr = resolveBashPath(target, homeDir, cwd);

            if (isProtected(resolvedStr)) {
                // Suppress if cwd and target are in the same extension directory.
                if (isSameExtension(cwd, resolvedStr)) continue;
                violations.push_back({"self-disabling", Severity::WARNING,
                    "Blocked redirect to protected path: " + resolvedStr});
            }
        }
    }

    // ── tee to protected paths ────────────────────────────────
    {
        std::string processed = dequote(command);
        static const std::regex tee_re("\\btee\\s+(?:-a\\s+)?(\\S+)");
        std::smatch m;
        if (std::regex_search(processed, m, tee_re)) {
            std::string target = m[1].str();
            std::string resolvedStr = resolveBashPath(target, homeDir, cwd);

            if (isProtected(resolvedStr) && !isSameExtension(cwd, resolvedStr)) {
                violations.push_back({"self-disabling", Severity::WARNING,
                    "Blocked tee to protected path: " + resolvedStr});
            }
        }
    }

    return violations;
}

// ── Shell-init content check ──────────────────────────────────
// Detect writes to shell init files that remove guardrail lines.

static bool isShellInitFile(const std::string& resolvedPath,
                             const std::string& homeDir) {
    static const char* SHELL_INIT_PATTERNS[] = {
        "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
        "~/.bash_login", "~/.bash_logout", "~/.bash_aliases",
        "~/.zprofile", "~/.zshenv", "~/.zlogin",
        nullptr
    };

    for (int i = 0; SHELL_INIT_PATTERNS[i] != nullptr; ++i) {
        std::string expanded = resolveTilde(SHELL_INIT_PATTERNS[i], homeDir);
        std::filesystem::path p;
        try {
            p = std::filesystem::weakly_canonical(expanded);
        } catch (const std::filesystem::filesystem_error&) {
            p = std::filesystem::path(expanded);
        }
        if (p.string() == resolvedPath) return true;
    }
    return false;
}

// Trim whitespace from both ends of a string.
static std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

// Convert string to lowercase.
static std::string toLower(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

// Check if a line contains an accepted guardrail marker.
static bool hasGuardrailMarker(const std::string& line) {
    std::string trimmed = trim(line);
    std::string lower = toLower(trimmed);

    if (trimmed.empty()) return false;

    // eval "$(tirith init ...)" — any tirith init eval form
    if (lower.find("eval") != std::string::npos &&
        lower.find("tirith init") != std::string::npos) {
        return true;
    }

    // tirith init (bare command)
    if (lower.find("tirith init") != std::string::npos) {
        return true;
    }

    // source .../guardrails/... (explicit source line)
    if (lower.find("source") != std::string::npos &&
        lower.find("guardrails") != std::string::npos) {
        return true;
    }

    // # guardrails:on (explicit user-controlled marker)
    if (lower.find("# guardrails:on") != std::string::npos) {
        return true;
    }

    return false;
}

std::vector<Violation> checkShellInitContent(const std::string& targetPath,
                                               const std::string& newContent,
                                               const std::string& homeDir,
                                               const std::string& cwd) {
    std::vector<Violation> violations;

    std::string expanded = resolveTilde(targetPath, homeDir);
    std::filesystem::path resolved;
    try {
        resolved = std::filesystem::weakly_canonical(expanded);
    } catch (const std::filesystem::filesystem_error&) {
        resolved = std::filesystem::path(expanded);
    }
    std::string resolvedStr = resolved.string();

    if (!isShellInitFile(resolvedStr, homeDir)) return violations;

    // Check each line for guardrail markers.
    bool hasMarker = false;
    {
        size_t pos = 0;
        while (pos < newContent.size()) {
            size_t end = newContent.find('\n', pos);
            if (end == std::string::npos) end = newContent.size();
            std::string line = newContent.substr(pos, end - pos);
            if (hasGuardrailMarker(line)) {
                hasMarker = true;
                break;
            }
            pos = end + 1;
        }
    }

    if (newContent.empty() || !hasMarker) {
        violations.push_back({"self-disabling", Severity::WARNING,
            "Shell init rewrite: " + resolvedStr +
            " — new content may remove guardrail initialization lines"
        });
    }

    return violations;
}
