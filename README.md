# pi-guardrails

Safety guardrails extension for the [pi coding agent](https://github.com/earendil-works/pi-coding-agent). Intercepts every tool call — `read`, `write`, `edit`, and `bash` — and checks it against a set of security rules implemented in a native C++ addon for zero-overhead pattern matching, plus [tirith](https://gettirith.com) for URL-based security analysis (download-and-execute, cloaking, etc.).

## What It Does

Guardrails prevents the coding agent from performing dangerous operations by classifying each tool call into one of two severity levels:

| Severity     | Behavior                                                          |
| ------------ | ----------------------------------------------------------------- |
| **Critical** | Auto-blocked — the tool call is rejected without user interaction |
| **Warning**  | Prompts the user for confirmation before allowing                 |

## Rule Modules

### A. Shell Composition (Critical)

Detects nested interpreters and code evaluators that bypass static analysis:

- `bash -c`, `sh -c`, `zsh -c`, `ksh -c`, `dash -c`, `fish -c`
- `python -c`, `python2 -c`, `python3 -c`
- `node -e`, `node --eval`
- `perl -e`, `perl -E`
- `ruby -e`, `ruby -E`
- `php -r`
- `eval` (standalone command)
- `exec` (process replacement, not fd redirection)
- Process substitution: `<(...)`, `>(...)`

### B. Process Control (Warning)

Detects commands that manage or background processes:

- `kill`, `killall`, `pkill`
- `nohup`
- `disown`
- Background operator `&` (not `&&`, `&>`, or `>&`)

### C. File Destruction (Warning)

Detects destructive file operations:

- `find ... -delete`
- `dd`
- `shred`

### D. Package Manager (Warning → Critical)

Detects package installs that can run arbitrary code via postinstall hooks:

- **npm**: `install`, `i`, `ci`, `add` (→ Critical with `-g`/`--global`)
- **yarn**: `install`, `add`
- **pnpm**: `install`, `i`, `add` (→ Critical with `-g`)
- **bun**: `install`, `add`
- **pip/pip3**: `install` (→ Critical with `--user`)
- **uv**: `pip install`, `add`
- **cargo**: `install`
- **gem**: `install`
- **go**: `install`
- **composer**: `install`, `require`
- **npx/pnpx/yarn dlx/bun x**: download-and-execute

### E. Sensitive Paths (Warning)

Detects writes to sensitive system, auth, and config paths via redirects (`>`, `>>`), `tee`, heredoc, `crontab`, `systemctl`, and `launchctl`:

- Shell init: `~/.bashrc`, `~/.zshrc`, `~/.profile`, etc.
- SSH: `~/.ssh/authorized_keys`, `~/.ssh/config`, `~/.ssh/id_*`
- Cloud auth: `~/.aws/credentials`, `~/.config/gcloud/**`, `~/.azure/**`
- Package auth: `~/.npmrc`, `~/.pypirc`, `~/.netrc`, `~/.docker/config.json`
- System: `/etc/**`, `/usr/local/etc/**`, cron files, systemd user units
- Git hooks: `**/.git/hooks/**`

### F. Self-Disabling (Warning)

Prevents the agent from modifying, removing, or bypassing the guardrail extension, pi itself, or tirith:

- **Path-based**: Blocks `write`/`edit` operations on extension files (`addon.node`, `index.ts`, `binding.gyp`, rule sources), pi config directory (`~/.pi/agent`), pi install directory, and tirith binary
- **Bash-based**: Blocks `rm`, `mv`, `cp`, `chmod`, `chown`, `chattr`, `ln`, `truncate`, `dd`, redirects, and `tee` targeting protected paths
- **Shell-init content**: Detects writes to shell init files that would remove guardrail initialization lines (`tirith init`, `pi`, `guardrails` markers)

### G. Path Escape (Warning)

Detects relative paths that use `..` to traverse outside the current working directory when using path-based tools (`read`, `write`, `edit`). Absolute paths are not flagged here — they are caught by the sensitive-path or self-disabling rules.

### H. Tirith URL Security (Critical / Warning)

When [tirith](https://gettirith.com) is installed (`which tirith`), every bash command is additionally checked via `tirith check --json --non-interactive`. This covers patterns the native rules don't catch:

- **Download-and-execute**: `curl ... | sh`, `wget ... | bash`, etc.
- **URL cloaking detection**: URLs that serve different content to bots vs browsers
- **Known-bad URL scoring**: tiered risk scoring against threat intelligence
- **MITRE ATT&CK mapping**: findings include technique IDs (e.g., T1059.004)

Tirith findings are mapped to guardrail severity (`HIGH`/`CRITICAL` → critical, others → warning) and merged with native violations before the final decision.

## Architecture

```
index.ts                          ← TypeScript extension entry point
  │                               ← hooks pi.on("tool_call")
  │                               ← merges native + tirith violations
  ├── native/build/Release/addon  ← C++ native addon (Node-API)
  │     addon.cpp                 ← NAPI bindings: init, checkPath, checkCommand, checkShellInitContent
  │     rules/
  │       rule.h                  ← Shared types (Violation, Severity) and declarations
  │       helpers.cpp             ← stripQuotes, splitPipeline, resolveTilde, glob matching
  │       shell-composition.cpp   ← Rule A
  │       process-control.cpp     ← Rule B
  │       file-destruction.cpp    ← Rule C
  │       package-manager.cpp     ← Rule D
  │       sensitive-paths.cpp     ← Rule E
  │       self-disabling.cpp      ← Rule F
  │     binding.gyp               ← node-gyp build configuration
  │     package.json              ← native addon dependencies (node-addon-api)
  │
  └── tirith (external binary)    ← URL security analysis via `tirith check`
      package.json                ← Extension metadata and pi extension entry
      tests/guardrails.test.js    ← Comprehensive test suite (node:test)
```

### Pipeline Splitting

Before running rules against a bash command, the command is split into pipeline segments on `;`, `&&`, `||`, and `|` (respecting quotes). Each segment is checked independently, so compounds like `echo ok && rm /path/to/extension/config` are caught on segment 2.

### JSON Output

The native addon and tirith both return JSON strings:

- `"null"` — no violations
- `[{ "category": "...", "severity": "critical"|"warning", "message": "..." } ]` — one or more violations

## Prerequisites

- **Node.js** (for the extension runtime)
- **tirith** (optional but recommended) — install from [gettirith.com](https://gettirith.com). The extension auto-detects it via `which tirith` and gracefully degrades if missing.

## Building

```bash
cd native
npm install        # installs node-addon-api
npm run build      # node-gyp rebuild
```

The compiled addon is placed at `native/build/Release/addon.node`.

## Tirith Integration

The extension calls `tirith check --json --non-interactive <command>` for every bash tool call. Tirith's exit code 1 (block) is handled gracefully — JSON output is parsed from stdout regardless of exit status.

Tirith findings are mapped to guardrail severity:

| Tirith severity | Guardrail severity      |
| --------------- | ----------------------- |
| `HIGH`          | `critical` (auto-block) |
| `CRITICAL`      | `critical` (auto-block) |
| `MEDIUM`        | `warning` (user prompt) |
| `LOW`           | `warning` (user prompt) |

No shell profile changes are needed — the extension acts as the tirith integration layer.

## Desktop Notifications

When guardrails pauses for user confirmation (warning-level violations), it fires a `notify-send` desktop notification so you're alerted even if the pi TUI isn't in focus. Requires `libnotify-bin` (`notify-send`); silently skipped if unavailable.

## Testing

```bash
node --test tests/guardrails.test.js
```

The test suite covers all rule modules with positive cases, negative cases (no false positives), severity levels, edge cases, JSON output format, multi-rule commands, pipeline splitting, and path escape checks.

## Installation

This extension is loaded automatically by pi when placed in the pi extensions directory. The `package.json` declares the extension entry point:

```json
{
  "pi": {
    "extensions": ["./index.ts"]
  }
}
```

## License

MIT — see [LICENSE](LICENSE).
