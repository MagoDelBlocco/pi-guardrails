#include "rule.h"
#include <regex>
#include <algorithm>

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
    std::string expanded = resolveTilde(rawPath, homeDir);
    // Resolve relative paths against the command's cwd.
    std::filesystem::path resolved;
    if (std::filesystem::path(expanded).is_absolute()) {
        resolved = std::filesystem::weakly_canonical(expanded);
    } else {
        resolved = std::filesystem::weakly_canonical(
            std::filesystem::path(cwd) / expanded
        );
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

    // ── Redirect targets (>, >>) ──────────────────────────────
    {
        auto targets = extractRedirectTargets(command);
        for (const auto& target : targets) {
            if (isSensitivePath(target, homeDir, cwd)) {
                violations.push_back({"sensitive-path", Severity::WARNING,
                    "Redirect to sensitive path: " + target});
            }
        }
    }

    // ── tee / tee -a targets ──────────────────────────────────
    {
        static const std::regex tee_re("\\btee\\s+(?:-a\\s+)?(\\S+)");
        std::smatch m;
        if (std::regex_search(command, m, tee_re)) {
            std::string target = m[1].str();
            if (isSensitivePath(target, homeDir, cwd)) {
                violations.push_back({"sensitive-path", Severity::WARNING,
                    "tee to sensitive path: " + target});
            }
        }
    }

    // ── Heredoc redirect: cat > <path> <<... ──────────────────
    // Only fire if the redirect check didn't already catch this path.
    {
        static const std::regex heredoc_re("\\bcat\\s+>\\s+(\\S+)\\s+<<");
        std::smatch m;
        if (std::regex_search(command, m, heredoc_re)) {
            std::string target = m[1].str();
            // Avoid duplicate: skip if redirect check already flagged it.
            bool alreadyFlagged = false;
            for (const auto& v : violations) {
                if (v.message.find(target) != std::string::npos) {
                    alreadyFlagged = true;
                    break;
                }
            }
            if (!alreadyFlagged && isSensitivePath(target, homeDir, cwd)) {
                violations.push_back({"sensitive-path", Severity::WARNING,
                    "Heredoc write to sensitive path: " + target});
            }
        }
    }

    // ── crontab (allow only -l; warn on -e, -, file arg, -r) ──
    {
        static const std::regex crontab_re("\\bcrontab\\b");
        if (std::regex_search(command, crontab_re)) {
            // Allow crontab -l only
            static const std::regex crontab_l("\\bcrontab\\s+-l\\b");
            if (!std::regex_search(command, crontab_l)) {
                violations.push_back({"sensitive-path", Severity::WARNING,
                    "crontab modification detected: can install persistent cron jobs"});
            }
        }
    }

    // ── systemctl --user enable/start/--now ────────────────────
    {
        static const std::regex systemctl_re("\\bsystemctl\\s+.*--user\\s+(enable|start|--now)\\b");
        if (std::regex_search(command, systemctl_re)) {
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
