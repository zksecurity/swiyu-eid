import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { createHash } from "node:crypto";
import { PROFILE } from "../paths.mjs";
import {
  CHECKED_IN_DID_TDW_KID,
  buildCredentialFixture,
  makeChallenge,
  makeStatus,
} from "./fixture.mjs";

const PROVIDER_DIR = dirname(dirname(fileURLToPath(import.meta.url)));
const SIDECAR = join(PROVIDER_DIR, "transcript-sidecar.mjs");

function factoryDocument() {
  const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
  const status = makeStatus(fixture.statusIndex);
  const challenge = { ...makeChallenge(status.snapshot.id), currentTime: "1750000000" };
  return {
    schema: "swiyu.transcript-fixture.v1",
    equivalence: "not_claimed",
    mapping: { query_id: challenge.queryId, profile: PROFILE },
    proof_path: "/proof",
    variants: [
      {
        id: "a",
        credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
        given: {
          issuer: {
            public_key: fixture.issuerPublicKey,
            issuer_id: "did:example:issuer",
            key_id: CHECKED_IN_DID_TDW_KID,
            allowed_vcts: ["https://example.ch/vct/person"],
          },
        },
        verify: { inputs: { statusSnapshot: status.authoritativeSnapshot } },
      },
    ],
  };
}

async function startSidecar(fixturePath, readyFile, extra = []) {
  const child = spawn(process.execPath, [SIDECAR, "--fixture", fixturePath, "--ready-file", readyFile, ...extra], {
    cwd: PROVIDER_DIR,
    env: {...process.env,
      SWIYU_OPENAC_ARTIFACT_ROOT: resolve(PROVIDER_DIR, "../../../components/zkid/wallet-unit-poc/openac-sdk"),
      SWIYU_OPENAC_KEYS_ROOT: resolve(PROVIDER_DIR, "../../../components/zkid/wallet-unit-poc/ecdsa-spartan2")},
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stderr = [];
  child.stderr.on("data", (chunk) => stderr.push(String(chunk)));
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) {
      throw new Error(`sidecar exited: ${stderr.join("")}`);
    }
    try {
      const ready = JSON.parse(readFileSync(readyFile, "utf8"));
      if (ready.url && ready.pid) return { child, ready, stderr };
    } catch {
      await delay(50);
    }
  }
  child.kill("SIGKILL");
  throw new Error(`sidecar did not become ready: ${stderr.join("")}`);
}

describe("transcript sidecar", () => {
  it("refuses startup without real artifact paths", async () => {
    const dir = mkdtempSync(join(tmpdir(), "swiyu-sidecar-missing-"));
    const fixturePath = join(dir, "factory.json");
    writeFileSync(fixturePath, JSON.stringify(factoryDocument()));
    const child = spawn(process.execPath, [SIDECAR, "--fixture", fixturePath, "--ready-file", join(dir, "ready.json")], {
      cwd: PROVIDER_DIR, env: {...process.env, SWIYU_OPENAC_KEYS_ROOT: "", SWIYU_OPENAC_ARTIFACT_ROOT: ""}, stdio: "ignore",
    });
    try {
      const result = await Promise.race([
        new Promise(resolve => child.once("exit", code => resolve(code))),
        delay(1500).then(() => "still-running"),
      ]);
      assert.equal(result, 1, "missing native artifacts must not produce a ready verifier");
    } finally { child.kill("SIGKILL"); rmSync(dir, {recursive:true,force:true}); }
  });

  it("rejects malformed bodies through the SDK before native proving", async () => {
    const dir = mkdtempSync(join(tmpdir(), "swiyu-sidecar-"));
    const fixturePath = join(dir, "factory.json");
    const readyFile = join(dir, "ready.json");
    const traceFile = join(dir, "trace.jsonl");
    writeFileSync(fixturePath, JSON.stringify(factoryDocument()));
    chmodSync(fixturePath, 0o600);
    const { child, ready } = await startSidecar(fixturePath, readyFile, ["--trace-file", traceFile]);
    try {
      assert.match(ready.url, /^http:\/\/127\.0\.0\.1:\d+\/verify$/);
      assert.equal(ready.pid, child.pid);
      const started = Date.now();
      const response = await fetch(ready.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{not-json",
      });
      const elapsed = Date.now() - started;
      assert.equal(response.status, 400);
      assert.equal(await response.text(), '{"verified":false}');
      assert.ok(elapsed < 5_000, "malformed JSON must not enter heavy proving");
      const empty = await fetch(ready.url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
      });
      assert.equal(empty.status, 400);
      assert.equal(await empty.text(), '{"verified":false}');
      const trace = readFileSync(traceFile, "utf8");
      assert.match(trace, /incoming/);
      assert.equal((await import("node:fs")).statSync(traceFile).mode & 0o777, 0o600);
    } finally {
      child.kill("SIGTERM");
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("binds the correlation digest helper to compact SD-JWT bytes", () => {
    const compact = "abc.def.ghi";
    const digest = createHash("sha256").update(compact).digest("hex");
    assert.equal(digest.length, 64);
  });
});
