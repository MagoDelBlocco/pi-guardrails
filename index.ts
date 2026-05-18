import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import * as path from "node:path";
import * as os from "node:os";
import { execSync } from "node:child_process";
import { createRequire } from "node:module";

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
	tirithBinary = execSync("which tirith 2>/dev/null", {
		encoding: "utf-8",
	}).trim();
} catch {
	// tirith not installed — no protection for it.
}

// Pi installation directory (directory containing the `pi` binary).
let piInstallDir = "/nonexistent";
try {
	const piPath = execSync("which pi 2>/dev/null", { encoding: "utf-8" }).trim();
	if (piPath) {
		piInstallDir = path.dirname(piPath);
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

function formatViolationPrompt(violations: Violation[]): string {
	return violations
		.map((v) => `[${v.severity.toUpperCase()}] ${v.category}: ${v.message}`)
		.join("\n");
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
				const violations = checkPathTool(
					ctx.cwd,
					filePath,
					event.toolName as "read" | "write" | "edit",
				);
				if (violations) {
					const critical = violations.filter((v) => v.severity === "critical");
					if (critical.length > 0) {
						return {
							block: true,
							reason: `Guardrail (auto-block): ${formatViolationPrompt(critical)}`,
						};
					}

					const prompt = formatViolationPrompt(violations);
					const allowed = await ctx.ui.confirm(
						"Guardrail violation",
						`${prompt}\n\nAllow access?`,
					);
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
				const violations = checkBashCommand(command, ctx.cwd);
				if (violations) {
					const critical = violations.filter((v) => v.severity === "critical");
					if (critical.length > 0) {
						return {
							block: true,
							reason: `Guardrail (auto-block): ${formatViolationPrompt(critical)}`,
						};
					}

					const warnings = violations.filter((v) => v.severity === "warning");
					const prompt = formatViolationPrompt(warnings);
					const allowed = await ctx.ui.confirm(
						"Guardrail violation",
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
