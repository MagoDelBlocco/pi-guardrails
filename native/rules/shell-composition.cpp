#include "rule.h"
#include <regex>

/*
 * Shell composition (Critical): detect nested interpreters, eval, exec,
 * and process substitution — all bypass static analysis.
 */

static bool wm(const std::string& haystack, const std::regex& pattern) {
    return std::regex_search(haystack, pattern);
}

std::vector<Violation> checkShellComposition(const std::string& command) {
    std::vector<Violation> violations;

    // ── Shell -c variants ──────────────────────────────────────

    // bash -c, sh -c, zsh -c, ksh -c, dash -c, fish -c
    static const std::regex shells_re("\\b(bash|sh|zsh|ksh|dash|fish)\\s+-[a-zA-Z]*c\\b");
    if (wm(command, shells_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "Shell -c detected: nested shell invocation bypasses guardrail analysis"});
    }

    // python -c (python, python2, python3)
    static const std::regex python_re("\\bpython[23]?\\s+-[a-zA-Z]*c\\b");
    if (wm(command, python_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "python -c detected: inline Python execution bypasses guardrail analysis"});
    }

    // node -e, node --eval
    static const std::regex node_e_re("\\bnode\\s+-[a-zA-Z]*e\\b");
    static const std::regex node_eval_re("\\bnode\\s+--eval\\b");
    if (wm(command, node_e_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "node -e detected: inline Node.js execution bypasses guardrail analysis"});
    }
    if (wm(command, node_eval_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "node --eval detected: inline Node.js execution bypasses guardrail analysis"});
    }

    // perl -e, perl -E
    static const std::regex perl_re("\\bperl\\s+-[a-zA-Z]*[eE]\\b");
    if (wm(command, perl_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "perl -e/-E detected: inline Perl execution bypasses guardrail analysis"});
    }

    // ruby -e, ruby -E
    static const std::regex ruby_re("\\bruby\\s+-[a-zA-Z]*[eE]\\b");
    if (wm(command, ruby_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "ruby -e/-E detected: inline Ruby execution bypasses guardrail analysis"});
    }

    // php -r
    static const std::regex php_re("\\bphp\\s+-[a-zA-Z]*r\\b");
    if (wm(command, php_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "php -r detected: inline PHP execution bypasses guardrail analysis"});
    }

    // ── eval as standalone command ─────────────────────────────
    // Match eval at start of pipeline segment: beginning of string, or
    // after ; | && || ( but not inside quotes or as a word substring.
    static const std::regex eval_re("(^|\\s|;|\\||&|\\()\\beval\\s");
    if (wm(command, eval_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "eval detected: evaluates arbitrary shell code bypassing guardrail analysis"});
    }

    // ── exec followed by a command (not fd redirection) ────────
    // exec 3>&1 is fd redirection (allow). exec /bin/bash is process replacement (block).
    // Heuristic: exec followed by a token that is NOT a digit or contains >& or <&
    static const std::regex exec_cmd_re("(^|\\s|;|\\||&|\\()\\bexec\\s+(?!\\d)[^&<>]");
    if (wm(command, exec_cmd_re)) {
        violations.push_back({"shell-composition", Severity::CRITICAL,
            "exec detected: process replacement bypasses guardrail analysis"});
    }

    // ── Process substitution <(...) and >(...) ─────────────────
    // These embed command sequences that bypass static analysis.
    // Check in blankQuoted form to avoid false positives inside strings.
    {
        std::string stripped = blankQuoted(command);
        if (stripped.find("<(") != std::string::npos ||
            stripped.find(">(") != std::string::npos) {
            violations.push_back({"shell-composition", Severity::CRITICAL,
                "Process substitution <(...) or >(...) detected: embedded commands bypass guardrail analysis"});
        }
    }

    return violations;
}
