import type { ExtensionAPI, Theme } from "@earendil-works/pi-coding-agent";
import * as path from "node:path";
import * as os from "node:os";
import { spawnSync, spawn } from "node:child_process";
import { createRequire } from "node:module";
import {
	type Component,
	Key,
	matchesKey,
	truncateToWidth,
	wrapTextWithAnsi,
} from "@earendil-works/pi-tui";

// jiti (pi's TS loader) can't handle .node binaries — use createRequire
// to get a native require that bypasses jiti's module resolution.
const nativeRequire = createRequire(path.resolve(__dirname, "index.ts"));
const native = nativeRequire("./native/build/Release/addon");

interface Violation {
	category: string;
	severity: "critical" | "warning";
	message: string;
}

// ── Resolved paths (cached at startup) ────────────────────────

// Extension root: directory containing this index.ts.
const extensionRoot = __dirname;

// Pi config directory: ~/.pi/agent
const piConfigDir = path.join(os.homedir(), ".pi", "agent");

// Tirith binary path (resolved via `which`).
let tirithBinary = "";
try {
	const result = spawnSync("which", ["tirith"], {
		encoding: "utf-8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (result.status === 0 && result.stdout) {
		tirithBinary = result.stdout.trim();
	}
} catch {
	// tirith not installed — no protection for it.
}

// Pi installation directory (directory containing the `pi` binary).
let piInstallDir = "/nonexistent";
try {
	const result = spawnSync("which", ["pi"], {
		encoding: "utf-8",
		stdio: ["ignore", "pipe", "pipe"],
	});
	if (result.status === 0 && result.stdout) {
		piInstallDir = path.dirname(result.stdout.trim());
	}
} catch {
	// pi not found — unlikely but safe to skip.
}

const homeDir = os.homedir();

// Initialize the native addon with protected paths.
native.init(
	extensionRoot,
	piConfigDir,
	piInstallDir,
	tirithBinary || "/nonexistent",
);

// ── Parsing ───────────────────────────────────────────────────

function parseViolations(raw: string): Violation[] | null {
	const parsed = JSON.parse(raw);
	if (parsed === null) return null;
	if (Array.isArray(parsed)) return parsed as Violation[];
	return [parsed as Violation];
}

function checkPathTool(
	cwd: string,
	targetPath: string,
	operation: "read" | "write" | "edit",
): Violation[] | null {
	const raw = native.checkPath(cwd, targetPath, operation, homeDir) as string;
	return parseViolations(raw);
}

function checkBashCommand(command: string, cwd: string): Violation[] | null {
	const raw = native.checkCommand(command, homeDir, cwd) as string;
	return parseViolations(raw);
}

// ── Tirith integration ────────────────────────────────────────
// Calls `tirith check --json --non-interactive <cmd>` to run URL-based
// security analysis (download-and-execute, cloaking, etc.).
// Uses spawnSync with arg array to bypass shell entirely (prevents
// command injection via $(...) or backtick expansion).

function checkTirith(command: string): Violation[] | null {
	if (!tirithBinary) return null;

	try {
		const result = spawnSync(
			tirithBinary,
			["check", "--json", "--non-interactive", command],
			{ encoding: "utf-8", cwd: homeDir },
		);

		// tirith returns exit code 1 on block — that's expected.
		// Parse stdout for findings regardless of exit code.
		if (result.stdout) {
			try {
				const parsed = JSON.parse(result.stdout);
				if (parsed.findings && parsed.findings.length > 0) {
					return parsed.findings.map((f: any) => ({
						category: f.rule_id,
						severity:
							f.severity === "HIGH" || f.severity === "CRITICAL"
								? "critical"
								: "warning",
						message: `${f.title}: ${f.description.split("\n")[0]}`,
					}));
				}
			} catch {
				// not JSON — ignore
			}
		}

		// Log unexpected exit codes (not 0=clean, not 1=block).
		if (result.status !== 0 && result.status !== 1) {
			console.warn(
				`[guardrails] Tirith exited with unexpected status ${result.status}:`,
				result.stderr || "(no stderr)",
			);
		}
	} catch (err: any) {
		// Genuine failure (e.g., binary missing, permission denied).
		console.warn(`[guardrails] Tirith check failed: ${err.message || err}`);
	}

	return null;
}

// Filter out self-disabling violations when editing from within the
// extension's own directory — the agent should be able to modify its own source.
function filterSelfDisabling(
	violations: Violation[] | null,
	cwd: string,
): Violation[] | null {
	if (cwd !== extensionRoot) return violations;
	if (!violations) return null;
	const filtered = violations.filter((v) => v.category !== "self-disabling");
	return filtered.length > 0 ? filtered : null;
}

function formatViolationPrompt(violations: Violation[]): string {
	return violations
		.map((v) => `[${v.severity.toUpperCase()}] ${v.category}: ${v.message}`)
		.join("\n");
}

// ── Desktop notification ──────────────────────────────────────
// Fires a `notify-send` so the user gets a system-level alert when
// guardrails prompts for permission.

function notifyUser(summary: string, body: string): void {
	try {
		spawn("notify-send", [summary, body], {
			detached: true,
			stdio: "ignore",
		}).unref();
	} catch {
		// notify-send not available — silently skip.
	}
}

// ── Confirm UI (overlay box matching ask_user styling) ─────────

const BOX_BORDER_LEFT = "│ ";
const BOX_BORDER_RIGHT = " │";
const BOX_BORDER_OVERHEAD = BOX_BORDER_LEFT.length + BOX_BORDER_RIGHT.length;

/** Top box border with optional title — mirrors ask_user styling. */
class BoxBorderTop implements Component {
	private color: (s: string) => string;
	private title?: string;
	private titleColor?: (s: string) => string;
	constructor(
		color: (s: string) => string,
		title?: string,
		titleColor?: (s: string) => string,
	) {
		this.color = color;
		this.title = title;
		this.titleColor = titleColor;
	}
	invalidate(): void {}
	render(width: number): string[] {
		const inner = Math.max(0, width - 2);
		if (!this.title || inner < this.title.length + 4) {
			return [this.color(`╭${"─".repeat(inner)}╮`)];
		}
		const label = ` ${this.title} `;
		const remaining = inner - 1 - label.length;
		const titleStyle = this.titleColor ?? this.color;
		return [
			this.color("╭─") +
				titleStyle(label) +
				this.color("─".repeat(Math.max(0, remaining)) + "╮"),
		];
	}
}

/** Bottom box border with optional label — mirrors ask_user styling. */
class BoxBorderBottom implements Component {
	private color: (s: string) => string;
	private label?: string;
	private labelColor?: (s: string) => string;
	constructor(
		color: (s: string) => string,
		label?: string,
		labelColor?: (s: string) => string,
	) {
		this.color = color;
		this.label = label;
		this.labelColor = labelColor;
	}
	invalidate(): void {}
	render(width: number): string[] {
		const inner = Math.max(0, width - 2);
		if (!this.label || inner < this.label.length + 4) {
			return [this.color(`╰${"─".repeat(inner)}╯`)];
		}
		const tag = ` ${this.label} `;
		const leftDashes = inner - tag.length - 1;
		const style = this.labelColor ?? this.color;
		return [
			this.color("╰" + "─".repeat(Math.max(0, leftDashes))) +
				style(tag) +
				this.color("─╯"),
		];
	}
}

/**
 * Confirm prompt component — styled as an overlay box matching ask_user.
 * Shows a message with [Yes] / [No] options, navigable with arrow keys.
 * Implements Component directly (not Container) to avoid input routing issues.
 */
class ConfirmComponent implements Component {
	private message: string;
	private theme: Theme;
	private onDone: (result: boolean | null) => void;
	private selectedIndex = 0;
	private choices = ["Yes", "No"];

	// Focusable — the TUI framework uses this to route input.
	private _focused = false;
	get focused(): boolean {
		return this._focused;
	}
	set focused(value: boolean) {
		this._focused = value;
	}

	constructor(
		message: string,
		theme: Theme,
		onDone: (result: boolean | null) => void,
	) {
		this.message = message;
		this.theme = theme;
		this.onDone = onDone;
	}

	invalidate(): void {}

	render(width: number): string[] {
		const innerWidth = Math.max(1, width - BOX_BORDER_OVERHEAD);
		const borderColor = (s: string) => this.theme.fg("accent", s);
		const titleColor = (s: string) => this.theme.fg("dim", this.theme.bold(s));

		// Build inner content
		const lines: string[] = [];

		// Title
		lines.push(this.theme.fg("accent", this.theme.bold("Permission required")));
		lines.push("");

		// Message (wrapped)
		const wrapped = wrapTextWithAnsi(
			this.message,
			Math.max(10, innerWidth - 2),
		);
		for (const line of wrapped) {
			lines.push(this.theme.fg("text", line));
		}
		lines.push("");

		// Choices
		for (let i = 0; i < this.choices.length; i++) {
			const selected = i === this.selectedIndex;
			const prefix = selected ? this.theme.fg("accent", "→") : " ";
			const label = selected
				? this.theme.fg("accent", this.theme.bold(this.choices[i]))
				: this.theme.fg("text", this.theme.bold(this.choices[i]));
			lines.push(`${prefix}  ${label}`);
		}
		lines.push("");

		// Help text
		lines.push(
			this.theme.fg("dim", "↑↓ navigate  •  enter confirm  •  esc cancel"),
		);
		lines.push("");

		// Render with borders
		const firstBorder = new BoxBorderTop(
			borderColor,
			"guardrails",
			titleColor,
		).render(width)[0];
		const lastBorder = new BoxBorderBottom(
			borderColor,
			"permission",
			(s: string) => this.theme.fg("dim", s),
		).render(width)[0];

		const bordered = lines.map((line, index) => {
			if (index === 0 || index === lines.length - 1) return line;
			const padded = truncateToWidth(line, innerWidth, "", true);
			return `${borderColor(BOX_BORDER_LEFT)}${padded}${borderColor(BOX_BORDER_RIGHT)}`;
		});

		return [firstBorder, ...bordered, lastBorder];
	}

	handleInput(data: string): void {
		if (matchesKey(data, Key.escape)) {
			this.onDone(null);
			return;
		}

		if (matchesKey(data, Key.up) || matchesKey(data, Key.ctrl("k"))) {
			this.selectedIndex =
				this.selectedIndex === 0
					? this.choices.length - 1
					: this.selectedIndex - 1;
			return;
		}

		if (matchesKey(data, Key.down) || matchesKey(data, Key.ctrl("j"))) {
			this.selectedIndex =
				this.selectedIndex === this.choices.length - 1
					? 0
					: this.selectedIndex + 1;
			return;
		}

		if (matchesKey(data, Key.enter)) {
			this.onDone(this.selectedIndex === 0);
			return;
		}
	}
}

// ── Confirm helper ────────────────────────────────────────────
// Wraps ctx.ui.custom() with ConfirmComponent, falling back to ctx.ui.confirm()
// in RPC/headless mode where custom() returns undefined.

async function askConfirm(
	ctx: { hasUI?: boolean; ui?: { custom: Function; confirm: Function } },
	message: string,
): Promise<boolean> {
	if (!ctx.hasUI || !ctx.ui) return false;

	const customResult = await ctx.ui.custom(
		(
			_tui: any,
			theme: Theme,
			_keybindings: any,
			done: (result: boolean | null) => void,
		) => new ConfirmComponent(message, theme, done),
		{
			overlay: true,
			overlayOptions: {
				anchor: "center" as const,
				width: "92%",
				minWidth: 40,
				maxHeight: "85%",
				margin: 1,
			},
		},
	);

	if (customResult !== undefined) {
		return !!(customResult as any);
	}

	// RPC/headless fallback
	const result = await ctx.ui.confirm("Guardrail violation", `${message}`);
	return !!result;
}

// ── Extension ──────────────────────────────────────────────────

export default function (pi: ExtensionAPI) {
	pi.on("session_start", async (_event, ctx) => {
		ctx.ui.notify("Guardrails active", "info");
	});

	pi.on("tool_call", async (event, ctx) => {
		// ── Path-based tools: read, write, edit ────────────────
		if (
			event.toolName === "read" ||
			event.toolName === "write" ||
			event.toolName === "edit"
		) {
			const filePath = (event.input as { path?: string }).path;
			if (filePath) {
				const violations = filterSelfDisabling(
					checkPathTool(
						ctx.cwd,
						filePath,
						event.toolName as "read" | "write" | "edit",
					),
					ctx.cwd,
				);

				// ── Shell-init content check ─────────────────────
				// For write operations, check if the new content would remove
				// guardrail initialization lines from a shell init file.
				if (event.toolName === "write") {
					const newContent = (event.input as { content?: string }).content;
					if (typeof newContent === "string") {
						const contentRaw = native.checkShellInitContent(
							filePath,
							newContent,
							homeDir,
							ctx.cwd,
						) as string;
						const contentViolations = parseViolations(contentRaw);
						if (contentViolations) {
							if (violations) {
								violations.push(...contentViolations);
							} else {
								// violations was null (no path violations), use content violations
								// We need to re-check since the if(violations) block below won't run
								const critical = contentViolations.filter(
									(v) => v.severity === "critical",
								);
								if (critical.length > 0) {
									return {
										block: true,
										reason: `Guardrail (auto-block): ${formatViolationPrompt(critical)}`,
									};
								}
								const prompt = formatViolationPrompt(contentViolations);
								notifyUser(
									"Guardrail: permission needed",
									contentViolations[0].message,
								);
								const allowed = await askConfirm(
									ctx,
									`${prompt}\n\nAllow access?`,
								);
								if (!allowed) {
									return {
										block: true,
										reason: "Guardrail: access denied by user",
									};
								}
							}
						}
					}
				}

				if (violations) {
					const critical = violations.filter((v) => v.severity === "critical");
					if (critical.length > 0) {
						return {
							block: true,
							reason: `Guardrail (auto-block): ${formatViolationPrompt(critical)}`,
						};
					}

					const prompt = formatViolationPrompt(violations);
					notifyUser("Guardrail: permission needed", violations[0].message);
					const allowed = await askConfirm(ctx, `${prompt}\n\nAllow access?`);
					if (!allowed) {
						return { block: true, reason: "Guardrail: access denied by user" };
					}
				}
			}
		}

		// ── Bash tool ─────────────────────────────────────────
		if (event.toolName === "bash") {
			const command = (event.input as { command?: string }).command;
			if (command) {
				// Combine native guardrail checks with tirith URL analysis.
				const violations: Violation[] = [];
				const nativeViolations = filterSelfDisabling(
					checkBashCommand(command, ctx.cwd),
					ctx.cwd,
				);
				if (nativeViolations) violations.push(...nativeViolations);
				const tirithViolations = checkTirith(command);
				if (tirithViolations) violations.push(...tirithViolations);

				if (violations.length > 0) {
					const critical = violations.filter((v) => v.severity === "critical");
					if (critical.length > 0) {
						return {
							block: true,
							reason: `Guardrail (auto-block): ${formatViolationPrompt(critical)}`,
						};
					}

					const warnings = violations.filter((v) => v.severity === "warning");
					const prompt = formatViolationPrompt(warnings);
					notifyUser("Guardrail: permission needed", warnings[0].message);
					const allowed = await askConfirm(
						ctx,
						`${prompt}\n\nAllow this command?`,
					);
					if (!allowed) {
						return { block: true, reason: "Guardrail: command denied by user" };
					}
				}
			}
		}
	});
}
