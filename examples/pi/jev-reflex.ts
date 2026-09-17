import { spawn } from "node:child_process";
import type { ExtensionAPI } from "@mariozechner/pi-coding-agent";

type JrxOutput = { block?: boolean; reason?: string };

function runJrx(payload: unknown): Promise<JrxOutput> {
  const args = ["pi-hook"];
  if (process.env.JRX_MODE) args.push("--mode", process.env.JRX_MODE);
  if (process.env.JRX_CONFIG) args.push("--config", process.env.JRX_CONFIG);

  return new Promise((resolve) => {
    const child = spawn("jev-reflex", args, {
      cwd: process.cwd(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    let stdout = "";
    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.on("error", () => {
      resolve({ block: true, reason: "JEV Reflex hook could not be started." });
    });
    child.on("close", () => {
      try {
        resolve(JSON.parse(stdout) as JrxOutput);
      } catch {
        resolve({ block: true, reason: "JEV Reflex hook returned invalid output." });
      }
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
