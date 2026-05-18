#include "rule.h"
#include <algorithm>
#include <cctype>

// ── stripQuotes ───────────────────────────────────────────────

std::string stripQuotes(const std::string& cmd) {
    std::string out;
    out.reserve(cmd.size());
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < cmd.size(); ++i) {
        char c = cmd[i];

        if (c == '\'' && !in_double) {
            in_single = !in_single;
            continue;
        }
        if (c == '"' && !in_single) {
            in_double = !in_double;
            continue;
        }
        if (c == '\\' && !in_single && !in_double && i + 1 < cmd.size()) {
            ++i; // skip escaped char
            continue;
        }
        if (!in_single && !in_double) {
            out += c;
        }
    }
    return out;
}

// ── resolveTilde ──────────────────────────────────────────────

std::string resolveTilde(const std::string& path, const std::string& home) {
    if (path.size() >= 1 && path[0] == '~') {
        if (path.size() == 1 || path[1] == '/') {
            return home + path.substr(1);
        }
        // ~user/... — handle ~user by finding the slash
        auto slash = path.find('/', 1);
        if (slash != std::string::npos) {
            // We don't resolve arbitrary ~user, just keep ~ as-is for those.
            // For our purposes this is fine — we mainly care about ~/.
        }
    }
    return path;
}

// ── extractRedirectTargets ────────────────────────────────────

std::vector<std::string> extractRedirectTargets(const std::string& cmd) {
    std::vector<std::string> targets;
    std::string stripped = stripQuotes(cmd);

    // Tokenize by whitespace, tracking operators.
    std::vector<std::string> tokens;
    {
        std::string cur;
        for (char c : stripped) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) tokens.push_back(cur);
    }

    for (size_t i = 0; i < tokens.size(); ++i) {
        const auto& t = tokens[i];
        // Detect > or >> (but not <> or &>)
        if ((t == ">" || t == ">>") && i + 1 < tokens.size()) {
            std::string target = tokens[i + 1];
            // Skip numeric-fd forms: if target is all digits or starts with digits&
            if (!target.empty() && std::isdigit(static_cast<unsigned char>(target[0]))) continue;
            targets.push_back(target);
        }
        // Also detect N> and N>> (numeric fd redirect) — skip those
        // Already handled by the digit check above.
    }

    return targets;
}

// ── extractFileArgs ───────────────────────────────────────────

std::vector<std::string> extractFileArgs(const std::string& cmd) {
    std::vector<std::string> args;
    std::string stripped = stripQuotes(cmd);

    // Split into tokens.
    std::vector<std::string> tokens;
    {
        std::string cur;
        for (char c : stripped) {
            if (std::isspace(static_cast<unsigned char>(c))) {
                if (!cur.empty()) { tokens.push_back(cur); cur.clear(); }
            } else {
                cur += c;
            }
        }
        if (!cur.empty()) tokens.push_back(cur);
    }

    // Find the command (first non-env-assignment token).
    size_t cmdIdx = 0;
    for (size_t i = 0; i < tokens.size(); ++i) {
        if (tokens[i].find('=') != std::string::npos &&
            tokens[i].find_first_of("=azAZ") == 0) {
            // Looks like VAR=value assignment
            cmdIdx = i + 1;
        } else {
            break;
        }
    }

    // Skip the command itself, then skip flags, collect file args.
    if (cmdIdx >= tokens.size()) return args;
    for (size_t i = cmdIdx + 1; i < tokens.size(); ++i) {
        const auto& t = tokens[i];
        if (t.size() >= 2 && t[0] == '-' && t[1] != '0' && t[1] != '1' &&
            t[1] != '2' && t[1] != '3' && t[1] != '4' && t[1] != '5' &&
            t[1] != '6' && t[1] != '7' && t[1] != '8' && t[1] != '9') {
            // Flag — skip
            continue;
        }
        if (t == "=" || t == "-") continue; // skip bare = or -
        args.push_back(t);
    }

    return args;
}

// ── splitPipeline ─────────────────────────────────────────────
// Split a command into pipeline segments on ; && || |
// Each segment is trimmed and non-empty.
std::vector<std::string> splitPipeline(const std::string& cmd) {
    std::vector<std::string> segments;
    std::string cur;
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; i < cmd.size(); ++i) {
        char c = cmd[i];

        // Track quotes to avoid splitting inside strings.
        if (c == '\'' && !in_double) {
            in_single = !in_single;
            cur += c;
            continue;
        }
        if (c == '"' && !in_single) {
            in_double = !in_double;
            cur += c;
            continue;
        }
        if (c == '\\' && !in_single && !in_double && i + 1 < cmd.size()) {
            cur += c;
            ++i;
            cur += cmd[i];
            continue;
        }

        // Split on ; and ||
        if (!in_single && !in_double && c == ';') {
            segments.push_back(cur);
            cur.clear();
            continue;
        }
        if (!in_single && !in_double && c == '|' &&
            i + 1 < cmd.size() && cmd[i + 1] == '|') {
            segments.push_back(cur);
            cur.clear();
            ++i; // skip second |
            continue;
        }
        if (!in_single && !in_double && c == '&' &&
            i + 1 < cmd.size() && cmd[i + 1] == '&') {
            segments.push_back(cur);
            cur.clear();
            ++i; // skip second &
            continue;
        }
        // Split on single | (pipe) — but not ||
        if (!in_single && !in_double && c == '|' &&
            (i + 1 >= cmd.size() || cmd[i + 1] != '|')) {
            segments.push_back(cur);
            cur.clear();
            continue;
        }

        cur += c;
    }
    if (!cur.empty()) segments.push_back(cur);

    return segments;
}

// ── matchesSensitivePattern ───────────────────────────────────

// Replace ~ with home dir in a pattern before matching.
static std::string expandPatternTilde(const std::string& pattern, const std::string& home) {
    if (pattern.size() >= 1 && pattern[0] == '~') {
        if (pattern.size() == 1 || pattern[1] == '/') {
            return home + pattern.substr(1);
        }
    }
    return pattern;
}

static bool globMatch(const std::string& text, const std::string& pat, size_t ti, size_t pi) {
    if (pi == pat.size()) return ti == text.size();

    // ** — match any sequence including /
    if (pat[pi] == '*' && pi + 1 < pat.size() && pat[pi + 1] == '*') {
        // **/ — skip the slash too
        size_t next = pi + 2;
        if (next < pat.size() && pat[next] == '/') ++next;
        // Try matching the rest of the pattern at every position
        for (size_t i = ti; i <= text.size(); ++i) {
            if (globMatch(text, pat, i, next)) return true;
        }
        return false;
    }

    // * — match anything except /
    if (pat[pi] == '*') {
        for (size_t i = ti; i < text.size(); ++i) {
            if (text[i] == '/') break;
            if (globMatch(text, pat, i + 1, pi + 1)) return true;
        }
        return false;
    }

    // ? — match any single char except /
    if (pat[pi] == '?') {
        return ti < text.size() && text[ti] != '/' &&
               globMatch(text, pat, ti + 1, pi + 1);
    }

    // Literal match
    return ti < text.size() && text[ti] == pat[pi] &&
           globMatch(text, pat, ti + 1, pi + 1);
}

bool matchesSensitivePattern(const std::filesystem::path& resolved,
                              const std::string& pattern,
                              const std::string& home) {
    std::string pat = expandPatternTilde(pattern, home);
    std::string resolvedStr = resolved.string();
    return globMatch(resolvedStr, pat, 0, 0);
}
