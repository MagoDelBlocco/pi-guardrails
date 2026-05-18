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
    static const std::regex global_re("(-g|--global)");
    return wm(command, global_re);
}

static bool hasUserFlag(const std::string& command) {
    static const std::regex user_re("--user");
    return wm(command, user_re);
}

std::vector<Violation> checkPackageManager(const std::string& command) {
    std::vector<Violation> violations;

    // ── npm ────────────────────────────────────────────────────
    static const std::regex npm_install_re("\\bnpm\\s+(install|i|ci|add)\\b");
    if (wm(command, npm_install_re)) {
        if (hasGlobalFlag(command)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "npm install with global flag detected: installs packages globally with postinstall hooks"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "npm install detected: postinstall hooks can run arbitrary code"});
        }
    }

    // ── yarn ───────────────────────────────────────────────────
    static const std::regex yarn_install_re("\\byarn\\s+(install|add)\\b");
    if (wm(command, yarn_install_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "yarn install detected: postinstall hooks can run arbitrary code"});
    }

    // ── pnpm ───────────────────────────────────────────────────
    static const std::regex pnpm_install_re("\\bpnpm\\s+(install|i|add)\\b");
    if (wm(command, pnpm_install_re)) {
        if (hasGlobalFlag(command)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "pnpm install with global flag detected: installs packages globally with postinstall hooks"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "pnpm install detected: postinstall hooks can run arbitrary code"});
        }
    }

    // ── bun ────────────────────────────────────────────────────
    static const std::regex bun_install_re("\\bbun\\s+(install|add)\\b");
    if (wm(command, bun_install_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "bun install detected: postinstall hooks can run arbitrary code"});
    }

    // ── pip / pip3 / uv pip ────────────────────────────────────
    static const std::regex pip_re("\\b(pip|pip3)\\s+install\\b");
    static const std::regex uv_pip_re("\\bu[vt]\\s+pip\\s+install\\b");
    static const std::regex uv_add_re("\\bu[vt]\\s+add\\b");
    if (wm(command, pip_re)) {
        if (hasUserFlag(command)) {
            violations.push_back({"package-manager", Severity::CRITICAL,
                "pip install --user detected: installs packages with postinstall hooks into user site-packages"});
        } else {
            violations.push_back({"package-manager", Severity::WARNING,
                "pip install detected: postinstall hooks can run arbitrary code"});
        }
    }
    if (wm(command, uv_pip_re) || wm(command, uv_add_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "uv pip install/add detected: postinstall hooks can run arbitrary code"});
    }

    // ── cargo install ──────────────────────────────────────────
    static const std::regex cargo_re("\\bcargo\\s+install\\b");
    if (wm(command, cargo_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "cargo install detected: compiles and installs to ~/.cargo/bin"});
    }

    // ── gem install ────────────────────────────────────────────
    static const std::regex gem_re("\\bgem\\s+install\\b");
    if (wm(command, gem_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "gem install detected: Ruby gems can run postinstall hooks"});
    }

    // ── go install ─────────────────────────────────────────────
    static const std::regex go_re("\\bgo\\s+install\\b");
    if (wm(command, go_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "go install detected: compiles and installs Go packages"});
    }

    // ── composer ───────────────────────────────────────────────
    static const std::regex composer_re("\\bcomposer\\s+(install|require)\\b");
    if (wm(command, composer_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "composer install/require detected: PHP packages can run post-install scripts"});
    }

    // ── npx / pnpx / yarn dlx / bun x / bunx (download-and-execute) ──
    static const std::regex npx_re("\\b(npx|pnpx)\\s+\\w");
    static const std::regex yarn_dlx_re("\\byarn\\s+dlx\\s+\\w");
    static const std::regex bun_x_re("\\bbun[\\s]x\\b|\\bbunx\\s+\\w");
    if (wm(command, npx_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "npx/pnpx detected: downloads and executes packages from the registry"});
    }
    if (wm(command, yarn_dlx_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "yarn dlx detected: downloads and executes packages from the registry"});
    }
    if (wm(command, bun_x_re)) {
        violations.push_back({"package-manager", Severity::WARNING,
            "bun x/bunx detected: downloads and executes packages from the registry"});
    }

    return violations;
}
