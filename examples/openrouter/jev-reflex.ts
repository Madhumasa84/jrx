import { spawn } from "node:child_process";

type JrxOutput = {
  block?: string;
  decision?: "allow" | "deny" | "ask_user";
  reason?: string;
};
type OpenRouterHookPayload = Record<string, unknown>;

function runJrx(payload: unknown): Promise<JrxOutput> {
  return new Promise((resolve) => {
    const child = spawn("jev-reflex", ["openrouter-hook"], {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", () => {
      resolve({ block: "JEV Reflex hook could not be started." });
    });
    child.on("close", () => {
      try {
        resolve(JSON.parse(stdout) as JrxOutput);
      } catch {
        resolve({ block: "JEV Reflex hook returned invalid output." });
      }
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

export const hooks = {
  PreToolUse: [
    {
      matcher: /.*/,
      handler: (payload: OpenRouterHookPayload) =>
        runJrx({ ...payload, hookName: "PreToolUse" }),
    },
  ],
  PermissionRequest: [
    {
      matcher: /.*/,
      handler: (payload: OpenRouterHookPayload) =>
        runJrx({ ...payload, hookName: "PermissionRequest" }),
    },
  ],
};
