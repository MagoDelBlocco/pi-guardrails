#include "rule.h"
#include <regex>
#include <algorithm>

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

// Resolve a path arg from a bash command: expand ~ then canonicalize relative to cwd.
static std::string resolveBashPath(const std::string& rawArg,
                                    const std::string& homeDir,
                                    const std::string& cwd) {
    std::string expanded = resolveTilde(rawArg, homeDir);
    if (std::filesystem::path(expanded).is_absolute()) {
        return std::filesystem::weakly_canonical(expanded).string();
    }
    return std::filesystem::weakly_canonical(
        std::filesystem::path(cwd) / expanded
    ).string();
}

} // anonymous namespace

void initSelfDisabling(const std::string& extensionRoot,
                        const std::string& piConfigDir,
                        const std::string& piInstallDir,
                        const std::string& tirithBinary) {
    protectedPaths.clear();
    protectedPrefixes.clear();

    auto add = [](const std::string& p) {
        if (p.empty()) return;
        std::filesystem::path resolved = std::filesystem::weakly_canonical(p);
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

    // Pi config directory and everything under it.
    add(piConfigDir);

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
                                               const std::string& homeDir) {
    std::vector<Violation> violations;

    // Only block writes and edits, not reads.
    if (operation != "write" && operation != "edit") return violations;

    // Resolve the target path.
    std::string expanded = resolveTilde(targetPath, homeDir);
    std::filesystem::path resolved = std::filesystem::weakly_canonical(expanded);
    std::string resolvedStr = resolved.string();

    if (isProtected(resolvedStr)) {
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

            if (isProtected(resolvedStr)) {
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
                violations.push_back({"self-disabling", Severity::WARNING,
                    "Blocked redirect to protected path: " + resolvedStr});
            }
        }
    }

    // ── tee to protected paths ────────────────────────────────
    {
        static const std::regex tee_re("\\btee\\s+(?:-a\\s+)?(\\S+)");
        std::smatch m;
        if (std::regex_search(command, m, tee_re)) {
            std::string target = m[1].str();
            std::string resolvedStr = resolveBashPath(target, homeDir, cwd);

            if (isProtected(resolvedStr)) {
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
        std::filesystem::path p = std::filesystem::weakly_canonical(expanded);
        if (p.string() == resolvedPath) return true;
    }
    return false;
}

std::vector<Violation> checkShellInitContent(const std::string& targetPath,
                                               const std::string& newContent,
                                               const std::string& homeDir,
                                               const std::string& cwd) {
    std::vector<Violation> violations;

    std::string expanded = resolveTilde(targetPath, homeDir);
    std::filesystem::path resolved = std::filesystem::weakly_canonical(expanded);
    std::string resolvedStr = resolved.string();

    if (!isShellInitFile(resolvedStr, homeDir)) return violations;

    bool hasTirithInit = newContent.find("tirith init") != std::string::npos;
    bool hasPiRef      = newContent.find("pi ") != std::string::npos;
    bool hasExtension  = newContent.find("guardrails") != std::string::npos;

    if (newContent.empty() || (!hasTirithInit && !hasPiRef && !hasExtension)) {
        violations.push_back({"self-disabling", Severity::WARNING,
            "Shell init rewrite: " + resolvedStr +
            " — new content may remove guardrail initialization lines"
        });
    }

    return violations;
}
