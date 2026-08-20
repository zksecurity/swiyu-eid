import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join } from "node:path";

const output = process.argv[2] ?? "/results/metadata.json";
const phase = process.argv[3] ?? "start";
const prior = existsSync(output) ? JSON.parse(readFileSync(output, "utf8")) : {};

if (phase === "start") {
  const artifacts = artifactFiles("/workspace/circom/build");
  const enforcedEnvelope = validateEnforcedEnvelope();
  const metadata = {
    schema: "swiyu.pinned-container-benchmark-metadata.v1",
    classification: "final-container-candidate",
    startedAt: new Date().toISOString(),
    image: {
      digest: process.env.BENCH_IMAGE_DIGEST,
      tag: process.env.BENCH_IMAGE_TAG,
      nodeBase: "node:22.14.0-bookworm-slim@sha256:1c18d9ab3af4585870b92e4dbc5cac5a0dc77dd13df1a5905cea89fc720eb05b",
      rustBase: "rust:1.91.0-bookworm@sha256:e187887ec511b3d93e45c0231d2f0fd59f1347526c58aa86343aa83c74f3e1a9",
      mavenBase: "maven:3.9.11-eclipse-temurin-21@sha256:6fdc855a6ed81d288ca7ca37ac6ff5e9308b612485c0801d70b25a858c83d237",
      platform: "linux/arm64",
    },
    limits: {
      requestedCpus: process.env.BENCH_CPUS,
      requestedCpuset: process.env.BENCH_CPUSET,
      requestedMemory: process.env.BENCH_MEMORY,
      cgroupCpuMax: optional("/sys/fs/cgroup/cpu.max"),
      cgroupCpusetEffective: optional("/sys/fs/cgroup/cpuset.cpus.effective"),
      cgroupMemoryMax: optional("/sys/fs/cgroup/memory.max"),
      cgroupPidsMax: optional("/sys/fs/cgroup/pids.max"),
      rayonThreads: process.env.RAYON_NUM_THREADS,
      network: process.env.BENCH_NETWORK,
      networkInterfaces: enforcedEnvelope.networkInterfaces,
      networkInterfaceStates: enforcedEnvelope.interfaceStates,
      requestedPids: process.env.BENCH_PIDS,
      enforcementValidated: true,
    },
    source: {
      commit: process.env.SOURCE_COMMIT,
      diffSha256: process.env.SOURCE_DIFF_SHA256,
      statusSha256: process.env.SOURCE_STATUS_SHA256,
      treeSha256: process.env.SOURCE_TREE_SHA256,
      dirty: process.env.SOURCE_DIRTY === "true",
    },
    productionVerifierSource: {
      repository: "swiyu-verifier",
      commit: process.env.SWIYU_VERIFIER_COMMIT,
      treeSha256: process.env.SWIYU_VERIFIER_TREE_SHA256,
      dirty: false,
    },
    host: {
      dockerVersion: process.env.BENCH_DOCKER_VERSION,
      os: process.env.BENCH_HOST_OS,
      architecture: process.env.BENCH_HOST_ARCH,
      cpu: process.env.BENCH_HOST_CPU,
      memoryBytes: process.env.BENCH_HOST_MEMORY_BYTES,
    },
    container: {
      osRelease: parseOsRelease(optional("/etc/os-release")),
      architecture: command("uname", "-m"),
      cpu: command("lscpu"),
      memory: optional("/proc/meminfo"),
    },
    tools: {
      node: command("node", "--version"),
      npm: command("npm", "--version"),
      rustc: command("rustc", "--version", "--verbose"),
      cargo: command("cargo", "--version"),
      circom: command("circom", "--version"),
      java: command("java", "--version"),
    },
    artifactSha256: Object.fromEntries(artifacts.map((path) => [
      path.replace("/workspace/", ""), sha256(path),
    ])),
    exactContainerCommand: process.env.BENCH_EXACT_COMMAND,
  };
  writeFileSync(output, `${JSON.stringify(metadata, null, 2)}\n`);
} else {
  const commandLog = process.env.BENCH_COMMAND_LOG;
  const commands = existsSync(commandLog)
    ? readFileSync(commandLog, "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line))
    : [];
  const entrypointExitCode = Number(process.argv[4] ?? "1");
  prior.finishedAt = new Date().toISOString();
  prior.commands = commands;
  prior.entrypointExitCode = entrypointExitCode;
  prior.completed = entrypointExitCode === 0 && commands.length > 0 &&
    commands.every((entry) => entry.exitCode === 0);
  writeFileSync(output, `${JSON.stringify(prior, null, 2)}\n`);
}

function artifactFiles(root) {
  const result = [];
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) visit(path);
      else if (path.endsWith(".r1cs") || path.endsWith(".wasm")) result.push(path);
    }
  };
  visit(root);
  return result.sort();
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
function optional(path) {
  return existsSync(path) ? readFileSync(path, "utf8").trim() : null;
}
function command(binary, ...args) {
  return execFileSync(binary, args, { encoding: "utf8" }).trim();
}
function parseOsRelease(text) {
  return Object.fromEntries((text ?? "").split("\n").filter(Boolean).map((line) => {
    const index = line.indexOf("=");
    return [line.slice(0, index), line.slice(index + 1).replace(/^"|"$/g, "")];
  }));
}

function validateEnforcedEnvelope() {
  const cpuMax = requiredFile("/sys/fs/cgroup/cpu.max");
  const [quotaText, periodText] = cpuMax.split(/\s+/);
  const quota = Number(quotaText);
  const period = Number(periodText);
  const requestedCpus = Number(process.env.BENCH_CPUS);
  if (!Number.isFinite(quota) || !Number.isFinite(period) || period <= 0 ||
      !Number.isFinite(requestedCpus) || requestedCpus <= 0 ||
      Math.abs(quota / period - requestedCpus) > 1e-9) {
    throw new Error(`CPU quota mismatch: requested=${process.env.BENCH_CPUS} effective=${cpuMax}`);
  }

  const effectiveCpuset = requiredFile("/sys/fs/cgroup/cpuset.cpus.effective");
  const requestedSet = cpuSet(process.env.BENCH_CPUSET ?? "");
  const effectiveSet = cpuSet(effectiveCpuset);
  if (JSON.stringify(requestedSet) !== JSON.stringify(effectiveSet)) {
    throw new Error(`CPU-set mismatch: requested=${process.env.BENCH_CPUSET} effective=${effectiveCpuset}`);
  }

  const effectiveMemory = Number(requiredFile("/sys/fs/cgroup/memory.max"));
  const requestedMemory = memoryBytes(process.env.BENCH_MEMORY ?? "");
  if (!Number.isSafeInteger(effectiveMemory) || effectiveMemory !== requestedMemory) {
    throw new Error(`memory limit mismatch: requested=${requestedMemory} effective=${effectiveMemory}`);
  }

  const effectivePids = Number(requiredFile("/sys/fs/cgroup/pids.max"));
  const requestedPids = Number(process.env.BENCH_PIDS);
  if (!Number.isSafeInteger(effectivePids) || effectivePids !== requestedPids) {
    throw new Error(`PID limit mismatch: requested=${requestedPids} effective=${effectivePids}`);
  }

  const networkInterfaces = readdirSync("/sys/class/net").sort();
  const interfaceStates = Object.fromEntries(networkInterfaces
    .filter((name) => existsSync(`/sys/class/net/${name}/operstate`))
    .map((name) => [name, requiredFile(`/sys/class/net/${name}/operstate`)]));
  const activeNonLoopback = Object.entries(interfaceStates)
    .filter(([name, state]) => name !== "lo" && state !== "down");
  const ipv4Routes = requiredFile("/proc/net/route").split("\n").slice(1).filter(Boolean);
  const ipv6NonLoopback = requiredFile("/proc/net/if_inet6").split("\n")
    .filter(Boolean)
    .filter((line) => line.trim().split(/\s+/).at(-1) !== "lo");
  if (process.env.BENCH_NETWORK !== "none" || activeNonLoopback.length > 0 ||
      ipv4Routes.length > 0 || ipv6NonLoopback.length > 0) {
    throw new Error(
      `offline-network mismatch: mode=${process.env.BENCH_NETWORK} ` +
      `active=${JSON.stringify(activeNonLoopback)} ipv4Routes=${ipv4Routes.length} ` +
      `ipv6NonLoopback=${ipv6NonLoopback.length}`,
    );
  }
  return { networkInterfaces, interfaceStates };
}

function requiredFile(path) {
  const value = optional(path);
  if (value === null) throw new Error(`required cgroup file is absent: ${path}`);
  return value;
}

function cpuSet(value) {
  const cpus = new Set();
  for (const part of value.split(",").filter(Boolean)) {
    const [startText, endText = startText] = part.split("-");
    const start = Number(startText);
    const end = Number(endText);
    if (!Number.isInteger(start) || !Number.isInteger(end) || start < 0 || end < start) {
      throw new Error(`invalid CPU set: ${value}`);
    }
    for (let cpu = start; cpu <= end; cpu++) cpus.add(cpu);
  }
  return [...cpus].sort((a, b) => a - b);
}

function memoryBytes(value) {
  const match = /^(\d+(?:\.\d+)?)([bkmg])?$/i.exec(value);
  if (!match) throw new Error(`invalid memory limit: ${value}`);
  const powers = { b: 1, k: 1024, m: 1024 ** 2, g: 1024 ** 3 };
  const result = Number(match[1]) * powers[(match[2] ?? "b").toLowerCase()];
  if (!Number.isSafeInteger(result)) throw new Error(`non-integral memory limit: ${value}`);
  return result;
}
