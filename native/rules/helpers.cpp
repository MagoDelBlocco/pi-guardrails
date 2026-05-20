#include "rule.h"
#include <algorithm>
#include <cctype>
#include <cstdlib>

// ── blankQuoted ───────────────────────────────────────────────
// Remove both quote characters AND their content.
// Use for payload-agnostic rules (shell-composition, process-control).
//   echo "a & b"  →  echo 
std::string blankQuoted(const std::string& cmd) {
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

// ── dequote ───────────────────────────────────────────────────
// Remove quote characters but PRESERVE content.
// Use for path-bearing rules (sensitive-paths, self-disabling, file-destruction).
//   rm "$HOME/.bashrc"  →  rm $HOME/.bashrc
//   echo "a > b"        →  echo a > b
std::string dequote(const std::string& cmd) {
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
        // In dequote: drop the backslash but keep the escaped char.
        if (c == '\\' && !in_single && !in_double && i + 1 < cmd.size()) {
            ++i; // skip backslash, keep next char
            out += cmd[i];
            continue;
        }
        out += c;
    }
    return out;
}

// ── expandVars ────────────────────────────────────────────────
// Expand shell variables in a string.
// Expands: $HOME, ${HOME}, $USER, ${USER},
//          $XDG_CONFIG_HOME, ${XDG_CONFIG_HOME},
//          $XDG_DATA_HOME, ${XDG_DATA_HOME},
//          $PWD, ${PWD}
std::string expandVars(const std::string& input,
                        const std::string& homeDir,
                        const std::string& cwd) {
    // Build variable map.
    struct VarEntry { const char* name; std::string value; };
    char* envUser = std::getenv("USER");
    char* envXdgConfig = std::getenv("XDG_CONFIG_HOME");
    char* envXdgData = std::getenv("XDG_DATA_HOME");
    char* envPwd = std::getenv("PWD");

    std::string userVal = envUser ? envUser : "";
    std::string xdgConfigVal = envXdgConfig ? envXdgConfig : (homeDir + "/.config");
    std::string xdgDataVal = envXdgData ? envXdgData : (homeDir + "/.local/share");
    std::string pwdVal = envPwd ? envPwd : cwd;

    VarEntry vars[] = {
        {"HOME", homeDir},
        {"USER", userVal},
        {"XDG_CONFIG_HOME", xdgConfigVal},
        {"XDG_DATA_HOME", xdgDataVal},
        {"PWD", pwdVal},
    };
    size_t numVars = sizeof(vars) / sizeof(vars[0]);

    std::string out;
    out.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '$' && i + 1 < input.size()) {
            // Check for ${VAR} form
            if (input[i + 1] == '{') {
                auto close = input.find('}', i + 2);
                if (close != std::string::npos) {
                    std::string varName = input.substr(i + 2, close - i - 2);
                    bool found = false;
                    for (size_t v = 0; v < numVars; ++v) {
                        if (varName == vars[v].name) {
                            out += vars[v].value;
                            i = close; // advance past }
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        // Not a known var — keep as-is
                        out += input[i];
                    }
                    continue;
                }
            }
            // Check for $VAR form (word chars)
            {
                size_t start = i + 1;
                size_t end = start;
                while (end < input.size() &&
                       (std::isalnum(static_cast<unsigned char>(input[end])) ||
                        input[end] == '_')) {
                    ++end;
                }
                if (end > start) {
                    std::string varName = input.substr(start, end - start);
                    bool found = false;
                    for (size_t v = 0; v < numVars; ++v) {
                        if (varName == vars[v].name) {
                            out += vars[v].value;
                            i = end - 1; // advance past var name
                            found = true;
                            break;
                        }
                    }
                    if (!found) {
                        // Not a known var — keep as-is
                        out += input[i];
                    }
                    continue;
                }
            }
        }
        out += input[i];
    }

    return out;
}

// ── normalizeRedirects ────────────────────────────────────────
// Insert spaces around > and >> operators so whitespace tokenization
// picks them up as separate tokens.
// Skips:
//   - Numeric fd redirects: 2>, 1>>, 2>> (digit immediately before >)
//   - Combined redirects: &>, &>> (preceded by &)
//   - Process substitution: >(...) (followed by ()
//   - Clobber-override: >| (followed by |)
std::string normalizeRedirects(const std::string& cmd) {
    std::string out;
    out.reserve(cmd.size() + 16);

    for (size_t i = 0; i < cmd.size(); ++i) {
        if (cmd[i] == '>') {
            // If prev char is also >, this is the second > of a >> sequence
            // that we already decided to skip (e.g., 2>>). Just pass it through.
            if (i > 0 && cmd[i - 1] == '>') {
                out += cmd[i];
                continue;
            }

            // Determine the full operator: > or >>
            bool isDouble = (i + 1 < cmd.size() && cmd[i + 1] == '>');

            // The "previous" char is the one before the ENTIRE operator.
            char prev = (i > 0) ? cmd[i - 1] : 0;

            // Skip numeric fd redirects: digit immediately before >
            // This handles 2>, 1>>, 2>> etc.
            bool prevDigit = std::isdigit(static_cast<unsigned char>(prev));

            // Skip combined redirects: &>, &>>
            bool prevAmp = (prev == '&');

            // Skip fd duplication: >& (only for single >, not >>)
            bool nextAmp = (!isDouble && i + 1 < cmd.size() && cmd[i + 1] == '&');

            // Skip process substitution: >(...) (only for single >)
            bool nextParen = (!isDouble && i + 1 < cmd.size() && cmd[i + 1] == '(');

            // Skip clobber-override: >| (only for single >)
            bool nextPipe = (!isDouble && i + 1 < cmd.size() && cmd[i + 1] == '|');

            if (!prevDigit && !prevAmp && !nextAmp && !nextParen && !nextPipe) {
                // Ensure space before operator
                if (i > 0 && out.back() != ' ') {
                    out += ' ';
                }
                if (isDouble) {
                    out += ">>";
                    ++i; // skip second >
                } else {
                    out += '>';
                }
                // Ensure space after operator
                if (i + 1 < cmd.size() && cmd[i + 1] != ' ') {
                    out += ' ';
                }
                continue;
            }
        }
        out += cmd[i];
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
// Extract redirect targets from a command segment.
// Only extracts > and >> operators that are OUTSIDE quotes.
// The target path after the operator is dequoted (quotes removed, content kept).

std::vector<std::string> extractRedirectTargets(const std::string& cmd) {
    std::vector<std::string> targets;

    // Step 1: Find positions of > operators that are OUTSIDE quotes.
    // We walk the raw command tracking quote state.
    struct RedirectOp {
        size_t pos;       // position of > in original string
        bool isDouble;    // true for >>
    };
    std::vector<RedirectOp> ops;

    {
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

            // Only look for > outside quotes
            if (!in_single && !in_double && c == '>') {
                // If prev char is also >, this is the second > of a >> sequence
                // that we already decided to skip (e.g., 2>>). Pass through.
                if (i > 0 && cmd[i - 1] == '>') continue;

                // Skip if preceded by a digit (numeric fd redirect: 2>, 1>>)
                if (i > 0 && std::isdigit(static_cast<unsigned char>(cmd[i - 1]))) continue;
                // Skip if preceded by & (combined redirect: &>, &>>)
                if (i > 0 && cmd[i - 1] == '&') continue;
                // Skip if followed by & (fd dup: >&)
                if (i + 1 < cmd.size() && cmd[i + 1] == '&') continue;
                // Skip process substitution: >(...)
                if (i + 1 < cmd.size() && cmd[i + 1] == '(') continue;
                // Skip clobber-override: >|
                if (i + 1 < cmd.size() && cmd[i + 1] == '|') continue;

                bool isDouble = (i + 1 < cmd.size() && cmd[i + 1] == '>');
                ops.push_back({i, isDouble});
            }
        }
    }

    // Step 2: For each redirect op, extract the target token after it.
    // Dequote the target so paths like "$HOME/.bashrc" become $HOME/.bashrc.
    for (const auto& op : ops) {
        size_t targetStart = op.pos + (op.isDouble ? 2 : 1);

        // Skip whitespace after the operator
        while (targetStart < cmd.size() && std::isspace(static_cast<unsigned char>(cmd[targetStart]))) {
            ++targetStart;
        }

        if (targetStart >= cmd.size()) continue;

        // Extract the target token (up to next whitespace or pipe/semicolon)
        size_t targetEnd = targetStart;
        while (targetEnd < cmd.size() &&
               !std::isspace(static_cast<unsigned char>(cmd[targetEnd])) &&
               cmd[targetEnd] != '|' && cmd[targetEnd] != ';' &&
               cmd[targetEnd] != '&') {
            ++targetEnd;
        }

        std::string rawTarget = cmd.substr(targetStart, targetEnd - targetStart);

        // Dequote the target: remove quotes but keep content.
        std::string target;
        {
            bool in_sq = false, in_dq = false;
            for (size_t i = 0; i < rawTarget.size(); ++i) {
                char c = rawTarget[i];
                if (c == '\'' && !in_dq) { in_sq = !in_sq; continue; }
                if (c == '"' && !in_sq) { in_dq = !in_dq; continue; }
                if (c == '\\' && !in_sq && !in_dq && i + 1 < rawTarget.size()) {
                    ++i; target += rawTarget[i]; continue;
                }
                target += c;
            }
        }

        // Skip numeric-fd forms
        if (!target.empty() && std::isdigit(static_cast<unsigned char>(target[0]))) continue;

        targets.push_back(target);
    }

    return targets;
}

// ── extractFileArgs ───────────────────────────────────────────

std::vector<std::string> extractFileArgs(const std::string& cmd) {
    std::vector<std::string> args;

    // Use dequote so file paths inside quotes remain visible.
    std::string stripped = dequote(cmd);

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
        size_t eq = tokens[i].find('=');
        if (eq != std::string::npos && eq > 0) {
            char c0 = tokens[i][0];
            bool valid_start = (c0 == '_' ||
                                (c0 >= 'A' && c0 <= 'Z') ||
                                (c0 >= 'a' && c0 <= 'z'));
            if (valid_start) {
                // Verify all chars before `=` are name-valid.
                bool name_ok = true;
                for (size_t j = 1; j < eq; ++j) {
                    char c = tokens[i][j];
                    if (!(c == '_' ||
                          (c >= 'A' && c <= 'Z') ||
                          (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9'))) {
                        name_ok = false; break;
                    }
                }
                if (name_ok) {
                    cmdIdx = i + 1;
                    continue;
                }
            }
        }
        break;
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
