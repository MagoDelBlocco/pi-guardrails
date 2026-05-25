#include "rule.h"
#include <regex>
#include <algorithm>
#include <set>

/*
 * Sensitive-path writes via bash (Warning).
 * Gates redirects, tee, heredoc, crontab, systemctl, launchctl
 * targeting sensitive system/auth/config paths.
 */

// Sensitive path patterns — expanded with home dir at check time.
static const char* SENSITIVE_PATTERNS[] = {
    // Shell init
    "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
    "~/.bash_login", "~/.bash_logout", "~/.bash_aliases",
    "~/.zprofile", "~/.zshenv", "~/.zlogin",
    "/etc/profile", "/etc/bash.bashrc", "/etc/zsh/**",

    // SSH
    "~/.ssh/authorized_keys", "~/.ssh/config", "~/.ssh/known_hosts",
    "~/.ssh/id_*",

    // Cloud / package auth
    "~/.aws/credentials", "~/.aws/config",
    "~/.config/gcloud/**",
    "~/.azure/**",
    "~/.npmrc", "~/.pypirc", "~/.gitconfig", "~/.netrc",
    "~/.docker/config.json",

    // System & persistence
    "/etc/**", "/usr/local/etc/**",
    "/etc/cron*", "/var/spool/cron/**",
    "~/.config/systemd/user/**",

    // Git hooks (anywhere — exception to cwd-escape model)
    "**/.git/hooks/**",

    nullptr
};

static bool isSensitivePath(const std::string& rawPath, const std::string& homeDir,
                             const std::string& cwd) {
    // Resolution order: dequote → expandVars → resolveTilde → weakly_canonical → match
    std::string expanded = expandVars(rawPath, homeDir, cwd);
    expanded = resolveTilde(expanded, homeDir);
    // Resolve relative paths against the command's cwd.
    // weakly_canonical can throw on permission-denied paths (e.g. /var/spool/cron/crontabs/root).
    // If resolution fails, fall back to the raw expanded path — the glob matcher
    // can still match it, and we avoid crashing the process.
    std::filesystem::path resolved;
    try {
        if (std::filesystem::path(expanded).is_absolute()) {
            resolved = std::filesystem::weakly_canonical(expanded);
        } else {
            resolved = std::filesystem::weakly_canonical(
                std::filesystem::path(cwd) / expanded
            );
        }
    } catch (const std::filesystem::filesystem_error&) {
        resolved = std::filesystem::path(expanded);
    }

    for (int i = 0; SENSITIVE_PATTERNS[i] != nullptr; ++i) {
        if (matchesSensitivePattern(resolved, SENSITIVE_PATTERNS[i], homeDir)) {
            return true;
        }
    }
    return false;
}

std::vector<Violation> checkSensitivePaths(const std::string& command,
                                            const std::string& homeDir,
                                            const std::string& cwd) {
    std::vector<Violation> violations;
    // Track seen targets to avoid duplicates (exact match, not substring).
    std::set<std::string> seenTargets;

    auto addViolation = [&](const std::string& category, Severity severity,
                            const std::string& message, const std::string& target) {
        if (seenTargets.count(target)) return;
        seenTargets.insert(target);
        violations.push_back({category, severity, message});
    };

    // ── Redirect targets (>, >>) ──────────────────────────────
    {
        auto targets = extractRedirectTargets(command);
        for (const auto& target : targets) {
            if (isSensitivePath(target, homeDir, cwd)) {
                addViolation("sensitive-path", Severity::WARNING,
                    "Redirect to sensitive path: " + target, target);
            }
        }
    }

    // ── tee / tee -a targets ──────────────────────────────────
    {
        // Use dequoted form so paths inside quotes are visible.
        std::string processed = dequote(command);
        static const std::regex tee_re("\\btee\\s+(?:-a\\s+)?(\\S+)");
        std::smatch m;
        if (std::regex_search(processed, m, tee_re)) {
            std::string target = m[1].str();
            if (isSensitivePath(target, homeDir, cwd)) {
                addViolation("sensitive-path", Severity::WARNING,
                    "tee to sensitive path: " + target, target);
            }
        }
    }

    // ── Heredoc redirect: cat > <path> <<... and variants ─────
    // Detects:
    //   cat > path <<EOF
    //   cat <<-EOF > path
    //   cat <<EOF > path
    //   tee path <<EOF
    //   tee -a path <<EOF
    //   dd of=path <<EOF
    {
        std::string processed = dequote(command);
        processed = normalizeRedirects(processed);

        // Check if there's a heredoc marker (<<)
        bool hasHeredoc = processed.find("<<") != std::string::npos;

        if (hasHeredoc) {
            // Extract redirect targets from the processed command
            // (normalizeRedirects already separated > from adjacent tokens)
            std::vector<std::string> tokens;
            {
                std::string cur;
                for (char c : processed) {
                    if (std::isspace(static_cast<unsigned char>(c))) {
                        if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
                    } else {
                        cur += c;
                    }
                }
                if (!cur.empty()) tokens.push_back(cur);
            }

            // Look for > or >> followed by a target
            for (size_t i = 0; i < tokens.size(); ++i) {
                if ((tokens[i] == ">" || tokens[i] == ">>") && i + 1 < tokens.size()) {
                    std::string target = tokens[i + 1];
                    if (!target.empty() && std::isdigit(static_cast<unsigned char>(target[0]))) continue;
                    if (isSensitivePath(target, homeDir, cwd)) {
                        addViolation("sensitive-path", Severity::WARNING,
                            "Heredoc write to sensitive path: " + target, target);
                    }
                }
            }

            // Look for tee path <<EOF form
            {
                static const std::regex tee_heredoc_re("\\btee\\s+(?:-a\\s+)?(\\S+)\\s+<<");
                std::smatch m;
                if (std::regex_search(processed, m, tee_heredoc_re)) {
                    std::string target = m[1].str();
                    if (isSensitivePath(target, homeDir, cwd)) {
                        addViolation("sensitive-path", Severity::WARNING,
                            "Heredoc tee to sensitive path: " + target, target);
                    }
                }
            }

            // Look for dd of=path <<EOF form
            {
                static const std::regex dd_heredoc_re("\\bdd\\b.*\\bof=(\\S+)");
                std::smatch m;
                if (std::regex_search(processed, m, dd_heredoc_re)) {
                    std::string target = m[1].str();
                    if (isSensitivePath(target, homeDir, cwd)) {
                        addViolation("sensitive-path", Severity::WARNING,
                            "Heredoc dd to sensitive path: " + target, target);
                    }
                }
            }
        }
    }

    // ── crontab (allow only -l/--list; warn on -e, -, file arg, -r) ──
    {
        static const std::regex crontab_re("\\bcrontab\\b");
        if (std::regex_search(command, crontab_re)) {
            // Allow crontab -l and crontab --list only
            static const std::regex crontab_l("\\bcrontab\\s+(-l|--list)\\b");
            if (!std::regex_search(command, crontab_l)) {
                violations.push_back({"sensitive-path", Severity::WARNING,
                    "crontab modification detected: can install persistent cron jobs"});
            }
        }
    }

    // ── systemctl --user enable/start/--now ────────────────────
    // Match either order: --user before or after the verb.
    {
        bool has_systemctl = std::regex_search(command, std::regex("\\bsystemctl\\b"));
        bool has_user     = std::regex_search(command, std::regex("(^|\\s)(--user|--global)(\\s|$)"));
        bool has_verb     = std::regex_search(command, std::regex("(^|\\s)(enable|start)(\\s|$)|(^|\\s)--now(\\s|$)"));
        if (has_systemctl && has_user && has_verb) {
            violations.push_back({"sensitive-path", Severity::WARNING,
                "systemctl --user enable/start detected: can install persistent user services"});
        }
    }

    // ── launchctl load/bootstrap (macOS forward-compat) ────────
    {
        static const std::regex launchctl_re("\\blaunchctl\\s+(load|bootstrap)\\b");
        if (std::regex_search(command, launchctl_re)) {
            violations.push_back({"sensitive-path", Severity::WARNING,
                "launchctl load/bootstrap detected: can install persistent macOS services"});
        }
    }

    return violations;
}

// ── Path-based sensitive-path check ───────────────────────────
// Called from checkPath (path-tool side) to catch writes to sensitive
// files even when no bash command is involved.

std::vector<Violation> checkSensitivePath(const std::string& targetPath,
                                            const std::string& operation,
                                            const std::string& homeDir,
                                            const std::string& cwd) {
    std::vector<Violation> violations;

    // Only check writes and edits, not reads.
    if (operation != "write" && operation != "edit") return violations;

    if (isSensitivePath(targetPath, homeDir, cwd)) {
        violations.push_back({"sensitive-path", Severity::WARNING,
            "Write to sensitive path: " + targetPath});
    }

    return violations;
}
