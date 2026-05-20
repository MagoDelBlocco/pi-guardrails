#include "rule.h"
#include <regex>

/*
 * Package-manager installs (Warning → Critical with global flags).
 * Postinstall/build hooks run arbitrary code.
 */

static bool wm(const std::string& haystack, const std::regex& pattern) {
    return std::regex_search(haystack, pattern);
}

static bool hasGlobalFlag(const std::string& command) {
    static const std::regex global_re("(^|\\s)(-g|--global)(\\s|$)");
    return wm(command, global_re);
}

static bool hasUserFlag(const std::string& command) {
    static const std::regex user_re("(^|\\s)--user(\\s|$)");
    return wm(command, user_re);
}

std::vector<Violation> checkPackageManager(const std::string& command) {
    std::vector<Violation> violations;

    // Use blankQuoted so commands inside quotes are invisible.
    // This prevents false positives like: bash -c 'npm install lodash'
    std::string processed = blankQuoted(command);

    // ── npm ────────────────────────────────────────────────────
    static const std::regex npm_install_re("\\bnpm\\s+(install|i|ci|add)\\b");
    if (wm(processed, npm_install_re)) {
        if (hasGlobalFlag(processed)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "npm install with global flag detected: installs packages globally with postinstall hooks"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "npm install detected: postinstall hooks can run arbitrary code"});
        }
    }

    // ── yarn ───────────────────────────────────────────────────
    static const std::regex yarn_install_re("\\byarn\\s+(install|add)\\b");
    if (wm(processed, yarn_install_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "yarn install detected: postinstall hooks can run arbitrary code"});
    }

    // ── yarn global add (separate rule — Critical) ─────────────
    static const std::regex yarn_global_re("\\byarn\\s+global\\s+add\\b");
    if (wm(processed, yarn_global_re)) {
        violations.push_back({"package-manager", Severity::CRITICAL,
            "yarn global add detected: installs globally with postinstall hooks"});
    }

    // ── pnpm ───────────────────────────────────────────────────
    static const std::regex pnpm_install_re("\\bpnpm\\s+(install|i|add)\\b");
    if (wm(processed, pnpm_install_re)) {
        if (hasGlobalFlag(processed)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "pnpm install with global flag detected: installs packages globally with postinstall hooks"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "pnpm install detected: postinstall hooks can run arbitrary code"});
        }
    }

    // ── bun ────────────────────────────────────────────────────
    static const std::regex bun_install_re("\\bbun\\s+(install|add)\\b");
    if (wm(processed, bun_install_re)) {
        if (hasGlobalFlag(processed)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "bun install with global flag detected: installs packages globally with postinstall hooks"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "bun install detected: postinstall hooks can run arbitrary code"});
        }
    }

    // ── pip / pip3 ─────────────────────────────────────────────
    static const std::regex pip_re("\\b(pip|pip3)\\s+install\\b");
    if (wm(processed, pip_re)) {
        if (hasUserFlag(processed)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "pip install --user detected: installs packages with postinstall hooks into user site-packages"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "pip install detected: postinstall hooks can run arbitrary code"});
        }
    }

    // ── pipx (install/run — downloads and runs Python packages) ─
    static const std::regex pipx_re("\\bpipx\\s+(install|run)\\b");
    if (wm(processed, pipx_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "pipx detected: downloads and runs Python packages"});
    }

    // ── uv pip install / uv add ────────────────────────────────
    static const std::regex uv_pip_re("\\buv\\s+pip\\s+install\\b");
    static const std::regex uv_add_re("\\buv\\s+add\\b");
    if (wm(processed, uv_pip_re) || wm(processed, uv_add_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "uv pip install/add detected: postinstall hooks can run arbitrary code"});
    }

    // ── cargo install ──────────────────────────────────────────
    static const std::regex cargo_re("\\bcargo\\s+install\\b");
    if (wm(processed, cargo_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "cargo install detected: compiles and installs to ~/.cargo/bin"});
    }

    // ── gem install ────────────────────────────────────────────
    static const std::regex gem_re("\\bgem\\s+install\\b");
    if (wm(processed, gem_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "gem install detected: Ruby gems can run postinstall hooks"});
    }

    // ── go install ─────────────────────────────────────────────
    static const std::regex go_re("\\bgo\\s+install\\b");
    if (wm(processed, go_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "go install detected: compiles and installs Go packages"});
    }

    // ── composer ───────────────────────────────────────────────
    static const std::regex composer_re("\\bcomposer\\s+(install|require)\\b");
    if (wm(processed, composer_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "composer install/require detected: PHP packages can run post-install scripts"});
    }

    // ── npx / pnpx / yarn dlx / bun x / bunx (download-and-execute) ──
    static const std::regex npx_re("\\b(npx|pnpx)\\s+\\w");
    static const std::regex yarn_dlx_re("\\byarn\\s+dlx\\s+\\w");
    static const std::regex bun_x_re("\\bbun[\\s]x\\b|\\bbunx\\s+\\w");
    if (wm(processed, npx_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "npx/pnpx detected: downloads and executes packages from the registry"});
    }
    if (wm(processed, yarn_dlx_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "yarn dlx detected: downloads and executes packages from the registry"});
    }
    if (wm(processed, bun_x_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "bun x/bunx detected: downloads and executes packages from the registry"});
    }

    return violations;
}
