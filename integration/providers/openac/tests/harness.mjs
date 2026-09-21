import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const PROVIDER_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const PROTOCOL = "swiyu.provider.v1";

export function providerDir() {
  return PROVIDER_DIR;
}

export function manifestPath() {
  return join(PROVIDER_DIR, "manifest.json");
}

export function providerCommand() {
  return { cwd: PROVIDER_DIR, cmd: process.execPath, args: ["provider.mjs"] };
}

export class ProviderProcess {
  constructor(env = {}) {
    const { cwd, cmd, args } = providerCommand();
    this.proc = spawn(cmd, args, {
      cwd,
      env: { ...process.env, ...env },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.rl = createInterface({ input: this.proc.stdout });
    this.pending = Promise.resolve();
    this.stderr = [];
    this.proc.stderr.on("data", (chunk) => this.stderr.push(String(chunk)));
  }

  async call(operation, payload = {}, id = crypto.randomUUID()) {
    const request = { protocol: PROTOCOL, id, operation, payload };
    const next = this.pending.then(() => this._exchange(request, id));
    this.pending = next.catch(() => {});
    return next;
  }

  async _exchange(request, expectedId) {
    return new Promise((resolve, reject) => {
      const onLine = (line) => {
        this.rl.off("line", onLine);
        let parsed;
        try {
          parsed = JSON.parse(line);
        } catch (err) {
          reject(new Error(`malformed provider JSON: ${line}`));
          return;
        }
        if (parsed.id !== expectedId) {
          reject(
            new Error(
              `response id mismatch: expected ${expectedId}, got ${parsed.id}`,
            ),
          );
          return;
        }
        resolve(parsed);
      };
      this.rl.on("line", onLine);
      this.proc.stdin.write(`${JSON.stringify(request)}\n`);
    });
  }

  async close() {
    try {
      await this.call("cleanup", {});
    } catch {
      /* ignore */
    }
    this.proc.stdin.end();
    await new Promise((resolve) => this.proc.once("exit", resolve));
  }
}

export function assertOk(response) {
  if (response.status !== "ok") {
    throw new Error(
      `expected ok, got ${response.status}: ${JSON.stringify(response.error)}`,
    );
  }
  return response.result;
}
