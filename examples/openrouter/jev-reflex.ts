import { spawn } from "node:child_process";

type JrxOutput = {
  block?: string;
  decision?: "allow" | "deny" | "ask_user";
  reason?: string;
};
type OpenRouterHookPayload = Record<string, unknown>;

// jrx answers every evaluation, including its own failures, with a JSON object and
// exit status 0. Anything else (no start, a crash, a non-zero exit, a non-object
// answer, or no answer before the deadline) blocks the tool call.
const TIMEOUT_MS = Number(process.env.JRX_HOOK_TIMEOUT_MS ?? 30_000);

function failClosed(hookName: string, reason: string): JrxOutput {
  return hookName === "PermissionRequest" ? { decision: "deny", reason } : { block: reason };
}

function runJrx(payload: OpenRouterHookPayload, hookName: string): Promise<JrxOutput> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (output: JrxOutput) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(output);
      }
    };
    const child = spawn("jev-reflex", ["openrouter-hook"], {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "ignore"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(failClosed(hookName, "JEV Reflex hook timed out."));
    }, TIMEOUT_MS);
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", () => {
      finish(failClosed(hookName, "JEV Reflex hook could not be started."));
    });
    child.on("close", (code: number | null) => {
      if (code !== 0) {
        finish(failClosed(hookName, "JEV Reflex hook exited unsuccessfully."));
        return;
      }
      try {
        const output: unknown = JSON.parse(stdout);
        if (output === null || typeof output !== "object" || Array.isArray(output)) {
          throw new Error("not an object");
        }
        finish(output as JrxOutput);
      } catch {
        finish(failClosed(hookName, "JEV Reflex hook returned invalid output."));
      }
    });
    child.stdin.on("error", () => {
      // The child exited before reading its input; "close" reports the outcome.
    });
    child.stdin.end(JSON.stringify({ ...payload, hookName }));
  });
}

export const hooks = {
  PreToolUse: [
    {
      matcher: /.*/,
      handler: (payload: OpenRouterHookPayload) => runJrx(payload, "PreToolUse"),
    },
  ],
  PermissionRequest: [
    {
      matcher: /.*/,
      handler: (payload: OpenRouterHookPayload) => runJrx(payload, "PermissionRequest"),
    },
  ],
};
