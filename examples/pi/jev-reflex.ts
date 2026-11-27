import { spawn } from "node:child_process";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

type JrxOutput = { block?: boolean; reason?: string };

// jrx answers every evaluation, including its own failures, with a JSON object and
// exit status 0. Anything else (no start, a crash, a non-zero exit, a non-object
// answer, or no answer before the deadline) blocks the tool call.
const TIMEOUT_MS = Number(process.env.JRX_HOOK_TIMEOUT_MS ?? 30_000);

function blocked(reason: string): JrxOutput {
  return { block: true, reason };
}

function runJrx(payload: unknown): Promise<JrxOutput> {
  // JRX_MODE and JRX_CONFIG come from the environment Pi was started with. Set them
  // from host configuration, not from anything the agent can change.
  const args = ["pi-hook"];
  if (process.env.JRX_MODE) args.push("--mode", process.env.JRX_MODE);
  if (process.env.JRX_CONFIG) args.push("--config", process.env.JRX_CONFIG);

  return new Promise((resolve) => {
    let settled = false;
    const finish = (output: JrxOutput) => {
      if (!settled) {
        settled = true;
        clearTimeout(timer);
        resolve(output);
      }
    };
    const child = spawn("jev-reflex", args, {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "ignore"],
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      finish(blocked("JEV Reflex hook timed out."));
    }, TIMEOUT_MS);
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", () => {
      finish(blocked("JEV Reflex hook could not be started."));
    });
    child.on("close", (code: number | null) => {
      if (code !== 0) {
        finish(blocked("JEV Reflex hook exited unsuccessfully."));
        return;
      }
      try {
        const output: unknown = JSON.parse(stdout);
        if (output === null || typeof output !== "object" || Array.isArray(output)) {
          throw new Error("not an object");
        }
        finish(output as JrxOutput);
      } catch {
        finish(blocked("JEV Reflex hook returned invalid output."));
      }
    });
    child.stdin.on("error", () => {
      // The child exited before reading its input; "close" reports the outcome.
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event) => {
    const output = await runJrx({
      toolName: event.toolName,
      input: event.input,
      cwd: process.cwd(),
    });
    if (output.block) {
      return {
        block: true,
        reason: output.reason ?? "Blocked by JEV Reflex.",
      };
    }
  });
}
