#ifndef GUARDRAIL_RULE_H
#define GUARDRAIL_RULE_H

#include <string>
#include <vector>
#include <set>
#include <filesystem>

enum class Severity {
    CRITICAL,   // auto-block
    WARNING     // prompt user, deny by default
};

struct Violation {
    std::string category;
    Severity    severity;
    std::string message;
};

/* ── shared helpers ─────────────────────────────────────────── */

// Blank quoted regions: remove both quote characters AND their content.
// Use for payload-agnostic rules (shell-composition, process-control)
// where anything inside quotes should be invisible to operator scans.
//   echo "a & b"  →  echo 
std::string blankQuoted(const std::string& cmd);

// Dequote: remove quote characters but PRESERVE content.
// Use for path-bearing rules (sensitive-paths, self-disabling, file-destruction)
// where the target path inside quotes must remain visible.
//   rm "$HOME/.bashrc"  →  rm $HOME/.bashrc
std::string dequote(const std::string& cmd);

// Expand shell variables in a path string.
// Expands: $HOME, ${HOME}, $USER, ${USER},
//          $XDG_CONFIG_HOME, ${XDG_CONFIG_HOME},
//          $XDG_DATA_HOME, ${XDG_DATA_HOME},
//          $PWD, ${PWD}
// Uses provided env values; falls back to defaults.
std::string expandVars(const std::string& input,
                        const std::string& homeDir,
                        const std::string& cwd);

// Normalize redirect operators: insert spaces around > and >> so that
// whitespace tokenization picks them up as separate tokens.
// Skips numeric fd redirects (2>, 1>>) and combined redirects (&>, >&).
//   echo x >~/.bashrc  →  echo x > ~/.bashrc
//   echo x>~/.bashrc   →  echo x > ~/.bashrc
//   echo x 2>/dev/null →  echo x 2>/dev/null  (unchanged)
std::string normalizeRedirects(const std::string& cmd);

// Resolve ~ in a path string using the given home directory.
std::string resolveTilde(const std::string& path, const std::string& home);

// Check if a resolved path matches a sensitive-path pattern.
// Supports ** (any depth) and * (single component) globs.
bool matchesSensitivePattern(const std::filesystem::path& resolved,
                              const std::string& pattern,
                              const std::string& home);

// Extract redirect targets from a command segment.
// Returns paths after > or >>, skipping numeric-fd forms (2>&1) and quoted >.
// Uses blankQuoted internally so operators inside quotes are ignored.
std::vector<std::string> extractRedirectTargets(const std::string& cmd);

// Extract file arguments from common file-manipulation commands.
// Strips flags (tokens starting with -) and returns remaining tokens.
// Uses blankQuoted internally.
std::vector<std::string> extractFileArgs(const std::string& cmd);

// Split a command into pipeline segments on ; && || |
std::vector<std::string> splitPipeline(const std::string& cmd);

/* ── rule modules ───────────────────────────────────────────── */

// A. Shell composition (Critical) — includes new interpreters, eval, exec, process substitution
std::vector<Violation> checkShellComposition(const std::string& command);

// B. Package-manager installs (Warning → Critical with global flags)
std::vector<Violation> checkPackageManager(const std::string& command);

// C. File destruction: basic destructive operations (Warning)
//    Only find -delete, dd, shred — redirect checking moved to sensitive-paths.
std::vector<Violation> checkFileDestruction(const std::string& command);

// D. Sensitive-path writes via bash (Warning)
//    Checks redirects, tee, heredoc, crontab, systemctl, launchctl against sensitive paths.
std::vector<Violation> checkSensitivePaths(const std::string& command,
                                            const std::string& homeDir,
                                            const std::string& cwd);

// E. Self-disabling protection (Warning, user prompt)
void initSelfDisabling(const std::string& extensionRoot,
                        const std::string& piConfigDir,
                        const std::string& piInstallDir,
                        const std::string& tirithBinary);

// Check a path-based tool call against self-disabling protected paths.
// operation: "read" | "write" | "edit"
std::vector<Violation> checkSelfDisablingPath(const std::string& targetPath,
                                               const std::string& operation,
                                               const std::string& homeDir);

// Check a bash command against self-disabling protected paths.
std::vector<Violation> checkSelfDisablingCommand(const std::string& command,
                                                   const std::string& homeDir,
                                                   const std::string& cwd);

// Check if writing `newContent` to `targetPath` would remove guardrail
// lines from a shell init file. Returns violations if guardrail markers
// (tirith init, pi-guardrails source, explicit marker) are absent from
// newContent but the target is a known shell init file.
std::vector<Violation> checkShellInitContent(const std::string& targetPath,
                                               const std::string& newContent,
                                               const std::string& homeDir,
                                               const std::string& cwd);

// Process control (Warning) — kill, nohup, disown, background &
std::vector<Violation> checkProcessControl(const std::string& command);

// Check a single path against sensitive-path patterns.
// Used by checkPath (path-tool side) to catch writes to sensitive files
// even when no bash command is involved.
std::vector<Violation> checkSensitivePath(const std::string& targetPath,
                                            const std::string& operation,
                                            const std::string& homeDir,
                                            const std::string& cwd);

#endif // GUARDRAIL_RULE_H
