import { appendFileSync, openSync, closeSync } from "node:fs";
import { spawnSync } from "node:child_process";

const separator = process.argv.indexOf("--");
if (separator < 0) throw new Error("run-recorded requires -- before the command");

const options = process.argv.slice(2, separator);
const command = process.argv.slice(separator + 1);
const id = value(options, "--id");
const cwd = value(options, "--cwd") ?? process.cwd();
const stdoutPath = value(options, "--stdout");
const env = { ...process.env };
for (let index = 0; index < options.length; index++) {
  if (options[index] === "--env") {
    const [key, ...rest] = options[++index].split("=");
    env[key] = rest.join("=");
  }
}

const startedAt = new Date().toISOString();
const stdout = stdoutPath ? openSync(stdoutPath, "w") : "inherit";
const result = spawnSync(command[0], command.slice(1), {
  cwd,
  env,
  stdio: ["ignore", stdout, "inherit"],
});
if (stdoutPath) closeSync(stdout);
const endedAt = new Date().toISOString();
const record = {
  id,
  startedAt,
  endedAt,
  cwd,
  argv: command,
  environmentOverrides: Object.fromEntries(
    Object.entries(env).filter(([key, val]) => process.env[key] !== val),
  ),
  stdoutPath: stdoutPath ?? null,
  exitCode: result.status,
  signal: result.signal,
};
appendFileSync(process.env.BENCH_COMMAND_LOG, `${JSON.stringify(record)}\n`);
if (result.error) throw result.error;
if (result.status !== 0) process.exit(result.status ?? 1);

function value(args, name) {
  const index = args.indexOf(name);
  return index < 0 ? undefined : args[index + 1];
}
