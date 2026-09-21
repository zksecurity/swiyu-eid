import { describe, it, before, after } from "node:test";
import assert from "node:assert/strict";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";
import { spawn } from "node:child_process";
import {
  ProviderProcess,
  assertOk,
  manifestPath,
  providerDir,
} from "./harness.mjs";
import { buildCredentialFixture, makeChallenge, makeStatus } from "./fixture.mjs";
import { artifactPaths, PROFILE, sdkRootImportUrl } from "../paths.mjs";

const PROTOCOL = "swiyu.provider.v1";
const realProofIt = process.env.SWIYU_OPENAC_REAL_E2E === "proof" ? it : it.skip;

function preparePayload(fixture, profile = PROFILE) {
  return {
    profile,
    credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
    context: { issuerPublicKey: fixture.issuerPublicKey },
  };
}

function fakeArtifactEnv() {
  const artifactRoot = mkdtempSync(join(tmpdir(), "openac-art-"));
  const keysRoot = mkdtempSync(join(tmpdir(), "openac-keys-"));
  mkdirSync(join(artifactRoot, "assets"), { recursive: true });
  writeFileSync(
    join(artifactRoot, "assets/swiyu_age18_status_2k.wasm"),
    Buffer.from([1, 2, 3]),
  );
  mkdirSync(join(keysRoot, "keys"), { recursive: true });
  writeFileSync(
    join(keysRoot, "keys/swiyu_age18_status_2k_proving.key"),
    Buffer.from("proving-key"),
  );
  writeFileSync(
    join(keysRoot, "keys/swiyu_age18_status_2k_verifying.key"),
    Buffer.from("verifying-key"),
  );
  mkdirSync(join(keysRoot, "target/release"), { recursive: true });
  const binPath = join(keysRoot, "target/release/swiyu-profile");
  writeFileSync(
    binPath,
    Buffer.from(`#!/usr/bin/env node
const fs = require("fs");
const path = require("path");
const PROFILE = "swiyu-age18-status-2k-v0";
const CIRCUIT = "swiyu_age18_status_2k";
const PROOF = "swiyu_age18_status_2k.proof";
const CONTEXT = "swiyu_age18_status_2k.public-context";
const [op, first, second] = process.argv.slice(2);
if (op === "prove") {
  const witness = fs.readFileSync(first);
  if (witness.length !== 320) {
    console.error("expected fake witness to contain public context");
    process.exit(1);
  }
  fs.writeFileSync(path.join(second, PROOF), witness);
  fs.writeFileSync(path.join(second, CONTEXT), witness);
  console.log("proof_bytes=" + witness.length + " context_bytes=" + witness.length);
} else if (op === "verify") {
  const proof = fs.readFileSync(path.join(first, PROOF));
  const context = fs.readFileSync(path.join(first, CONTEXT));
  if (Buffer.compare(proof, context) !== 0) {
    console.error("expected public context mismatch");
    process.exit(1);
  }
  console.log("verified profile=" + PROFILE + " circuit=" + CIRCUIT);
} else {
  console.error("unknown op: " + op);
  process.exit(2);
}
`),
  );
  chmodSync(binPath, 0o755);
  return {
    env: {
      SWIYU_OPENAC_ARTIFACT_ROOT: artifactRoot,
      SWIYU_OPENAC_KEYS_ROOT: keysRoot,
      SWIYU_OPENAC_TEST_FAKE_WITNESS: "1",
    },
    artifactRoot,
    keysRoot,
  };
}

function swiyuLifecyclePayload(fixture) {
  const { snapshot, authoritativeSnapshot, witness } = makeStatus(fixture.statusIndex);
  const challenge = makeChallenge(snapshot.id);
  return {
    challenge,
    presentInputs: {
      holderPrivateKeyHex: fixture.holderPrivateKeyHex,
      statusSnapshot: snapshot,
      statusWitness: witness,
    },
    verifyInputs: {
      issuerPublicKey: fixture.issuerPublicKey,
      statusSnapshot: authoritativeSnapshot,
    },
  };
}

describe("openac provider adapter", () => {
  let client;

  before(async () => {
    client = new ProviderProcess();
  });

  after(async () => {
    await client.close();
  });

  it("manifest declares native OpenAC proof coverage", () => {
    const manifest = JSON.parse(readFileSync(manifestPath(), "utf8"));
    assert.equal(manifest.schema, "swiyu.provider-manifest.v1");
    assert.equal(manifest.kind, "implementation");
    assert.equal(manifest.incomplete, false);
    assert.deepEqual(manifest.profiles, [PROFILE, "openac-age25-jwt-v0"]);
    assert.ok(manifest.circuits.includes("swiyu_age25_jwt"));
    assert.deepEqual(manifest.command, ["node", "provider.mjs"]);
    assert.equal(manifest.coverage.verify, "native-swiyu-profile");
  });

  it("normalizes explicit artifact env roots before native backend use", () => {
    const oldArtifactRoot = process.env.SWIYU_OPENAC_ARTIFACT_ROOT;
    const oldKeysRoot = process.env.SWIYU_OPENAC_KEYS_ROOT;
    try {
      process.env.SWIYU_OPENAC_ARTIFACT_ROOT = relative(
        process.cwd(),
        resolve(providerDir(), "..", "openac-artifacts"),
      );
      process.env.SWIYU_OPENAC_KEYS_ROOT = relative(
        process.cwd(),
        resolve(providerDir(), "..", "openac-keys"),
      );
      const paths = artifactPaths();
      assert.equal(isAbsolute(paths.artifactRoot), true);
      assert.equal(isAbsolute(paths.keysRoot), true);
      assert.equal(paths.artifactRoot, resolve(paths.artifactRoot));
      assert.equal(paths.keysRoot, resolve(paths.keysRoot));
      assert.equal(paths.provingKey, resolve(paths.provingKey));
      assert.equal(paths.verifyingKey, resolve(paths.verifyingKey));
      assert.equal(paths.nativeBinary, resolve(paths.nativeBinary));
    } finally {
      if (oldArtifactRoot === undefined) {
        delete process.env.SWIYU_OPENAC_ARTIFACT_ROOT;
      } else {
        process.env.SWIYU_OPENAC_ARTIFACT_ROOT = oldArtifactRoot;
      }
      if (oldKeysRoot === undefined) {
        delete process.env.SWIYU_OPENAC_KEYS_ROOT;
      } else {
        process.env.SWIYU_OPENAC_KEYS_ROOT = oldKeysRoot;
      }
    }
  });

  it("imports the SDK root entry for the real witness calculator", async () => {
    const mod = await import(sdkRootImportUrl());
    assert.equal(typeof mod.WitnessCalculator, "function");
  });

  it("initialize reports honest operation readiness", async () => {
    const res = await client.call("initialize", {});
    const result = assertOk(res);
    assert.equal(result.targetProfile, PROFILE);
    assert.deepEqual(result.profiles, [PROFILE, "openac-age25-jwt-v0"]);
    assert.deepEqual(result.circuits, ["swiyu_age18_status_2k", "swiyu_age25_jwt"]);
    assert.ok(result.operationReadiness);
    assert.equal(result.operationReadiness.prepare.status, "implemented");
    assert.equal(result.operationReadiness.prepare.coverage, "sdk-parse-precompute");
    assert.equal(result.operationReadiness.present.status, "unavailable");
    assert.equal(result.operationReadiness.verify.status, "unavailable");
    assert.equal(result.operationReadiness.verify.reason, "ARTIFACTS_MISSING");
    assert.equal(result.capabilities, undefined);
    assert.equal(typeof result.artifacts.available, "boolean");
    assert.equal(result.artifacts.available, false);
    assert.ok(Array.isArray(result.artifacts.missing));
    assert.ok(result.artifacts.missing.length > 0);
    assert.ok(result.artifacts.envRequired.includes("SWIYU_OPENAC_ARTIFACT_ROOT"));
    assert.ok(result.artifacts.available_files);
    assert.match(result.artifacts.provenance, /not verified/);
    assert.equal(result.sdkProfile, PROFILE);
  });

  it("declares the shared age-25 profile without a packaged prover", async () => {
    const res = await client.call("prepare", {
      profile: "openac-age25-jwt-v0",
      credential: { format: "dc+sd-jwt", data: "x.y.z" },
    });
    assert.equal(res.status, "unsupported");
    assert.equal(res.error.code, "unsupported_profile");
    assert.match(res.error.message, /circuit-source only/);
    assert.equal(res.error.circuit, "swiyu_age25_jwt");
    assert.equal(res.error.claim, "swiyu.shared.age25-holder-challenge.v0");
  });

  it("prepares synthetic credential via SDK", async () => {
    const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const res = await client.call("prepare", preparePayload(fixture));
    const result = assertOk(res);
    assert.match(result.handle, /^[0-9a-f-]{36}$/);
    assert.equal(result.metadata.profile, PROFILE);
    assert.equal(result.metadata.circuitId, "swiyu_age18_status_2k");
    assert.equal(result.metadata.stage, "parsed");
    assert.equal(result.metadata.coverage, "sdk-parse-precompute");
  });

  it("rejects malformed credential with sanitized error", async () => {
    const fixture = buildCredentialFixture();
    const res = await client.call(
      "prepare",
      preparePayload({ ...fixture, compactSdJwt: "not-a-jwt" }),
    );
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "bad_credential");
    assert.match(res.error.message, /could not be parsed/);
    assert.doesNotMatch(res.error.message, /not-a-jwt/);
  });

  it("rejects missing issuerPublicKey", async () => {
    const fixture = buildCredentialFixture();
    const res = await client.call("prepare", {
      profile: PROFILE,
      credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
      context: {},
    });
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "bad_credential");
  });

  it("rejects private JWK d in issuerPublicKey", async () => {
    const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const res = await client.call("prepare", {
      profile: PROFILE,
      credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
      context: {
        issuerPublicKey: { ...fixture.issuerPublicKey, d: "private-material" },
      },
    });
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "bad_credential");
    assert.match(res.error.message, /must not include private JWK field d/);
  });

  it("rejects unsupported profile", async () => {
    const fixture = buildCredentialFixture();
    const res = await client.call(
      "prepare",
      preparePayload(fixture, "swiyu-unknown-v0"),
    );
    assert.equal(res.status, "unsupported");
    assert.equal(res.error.code, "unsupported_profile");
  });

  it("present returns ARTIFACTS_MISSING when env paths absent", async () => {
    const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const prep = assertOk(await client.call("prepare", preparePayload(fixture)));
    const res = await client.call("present", {
      profile: PROFILE,
      handle: prep.handle,
      request_context: { nonce: "n1" },
      inputs: {},
    });
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "ARTIFACTS_MISSING");
    assert.ok(res.error.envRequired.includes("SWIYU_OPENAC_ARTIFACT_ROOT"));
  });

  it("rejects stale handle after cleanup", async () => {
    const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const prep = assertOk(await client.call("prepare", preparePayload(fixture)));
    assertOk(await client.call("cleanup", {}));
    const res = await client.call("present", {
      profile: PROFILE,
      handle: prep.handle,
      request_context: {},
      inputs: {},
    });
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "bad_handle");
  });

  it("verify returns ARTIFACTS_MISSING without explicit env paths", async () => {
    const res = await client.call("verify", {
      profile: PROFILE,
      presentation: "opaque",
      request_context: {},
      inputs: {},
    });
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "ARTIFACTS_MISSING");
  });

  it("verify rejects malformed opaque presentations even when artifacts exist", async () => {
    const { env, artifactRoot, keysRoot } = fakeArtifactEnv();
    const scoped = new ProviderProcess(env);
    try {
      const res = await scoped.call("verify", {
        profile: PROFILE,
        presentation: "opaque-presentation",
        request_context: {},
        inputs: {},
      });
      assert.equal(res.status, "error");
      assert.equal(res.error.code, "bad_presentation");
      assert.equal(res.result?.verified, undefined);
    } finally {
      await scoped.close();
      rmSync(artifactRoot, { recursive: true, force: true });
      rmSync(keysRoot, { recursive: true, force: true });
    }
  });

  it("presents and verifies through the swiyu wallet/verifier backend", async () => {
    const { env, artifactRoot, keysRoot } = fakeArtifactEnv();
    const scoped = new ProviderProcess(env);
    try {
      const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
      const prepared = assertOk(await scoped.call("prepare", preparePayload(fixture)));
      const payload = swiyuLifecyclePayload(fixture);
      const present = assertOk(await scoped.call("present", {
        profile: PROFILE,
        handle: prepared.handle,
        request_context: payload.challenge,
        inputs: payload.presentInputs,
      }));
      assert.equal(typeof present.presentation, "string");
      assert.ok(present.presentation.length > 100);
      assert.equal(present.artifact_sizes.witness, 320);
      assert.equal(present.artifact_sizes.proof, 320);
      assert.equal(present.public_outputs.profile, PROFILE);
      assert.equal(present.public_outputs.circuit_id, "swiyu_age18_status_2k");

      const verified = assertOk(await scoped.call("verify", {
        profile: PROFILE,
        presentation: present.presentation,
        request_context: payload.challenge,
        inputs: payload.verifyInputs,
      }));
      assert.equal(verified.verified, true);
      assert.equal(verified.profile, PROFILE);
      assert.equal(verified.circuit_id, "swiyu_age18_status_2k");

      const rejected = assertOk(await scoped.call("verify", {
        profile: PROFILE,
        presentation: present.presentation,
        request_context: { ...payload.challenge, nonce: `${payload.challenge.nonce}-bad` },
        inputs: payload.verifyInputs,
      }));
      assert.equal(rejected.verified, false);
      assert.match(rejected.reason, /context|verify|proof/i);
    } finally {
      await scoped.close();
      rmSync(artifactRoot, { recursive: true, force: true });
      rmSync(keysRoot, { recursive: true, force: true });
    }
  });

  realProofIt(
    "presents and verifies through the real OpenAC circuit artifacts",
    { timeout: 3 * 60_000 },
    async () => {
      const paths = artifactPaths();
      const tempRoot = mkdtempSync(join(tmpdir(), "openac-real-provider-"));
      const scoped = new ProviderProcess({
        SWIYU_OPENAC_ARTIFACT_ROOT:
          process.env.SWIYU_OPENAC_ARTIFACT_ROOT ?? paths.sdkRoot,
        SWIYU_OPENAC_KEYS_ROOT:
          process.env.SWIYU_OPENAC_KEYS_ROOT ??
          join(paths.repoRoot, "components/zkid/wallet-unit-poc/ecdsa-spartan2"),
        SWIYU_OPENAC_TEMP_ROOT: tempRoot,
      });
      try {
        const init = assertOk(await scoped.call("initialize", {}));
        assert.equal(init.artifacts.available, true);

        const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
        const prepared = assertOk(await scoped.call("prepare", preparePayload(fixture)));
        const payload = swiyuLifecyclePayload(fixture);
        const started = performance.now();
        const present = assertOk(await scoped.call("present", {
          profile: PROFILE,
          handle: prepared.handle,
          request_context: payload.challenge,
          inputs: payload.presentInputs,
        }));
        const proveMs = performance.now() - started;
        assert.equal(typeof present.presentation, "string");
        assert.ok(present.presentation.length > 100_000);
        assert.ok(present.artifact_sizes.witness > 100_000);
        assert.ok(present.artifact_sizes.proof > 100_000);

        const verifyStarted = performance.now();
        const verified = assertOk(await scoped.call("verify", {
          profile: PROFILE,
          presentation: present.presentation,
          request_context: payload.challenge,
          inputs: payload.verifyInputs,
        }));
        const verifyMs = performance.now() - verifyStarted;
        assert.equal(verified.verified, true);

        const rejected = assertOk(await scoped.call("verify", {
          profile: PROFILE,
          presentation: present.presentation,
          request_context: { ...payload.challenge, nonce: `${payload.challenge.nonce}-bad` },
          inputs: payload.verifyInputs,
        }));
        assert.equal(rejected.verified, false);
        console.log(JSON.stringify({
          phase: "provider-real-proof",
          proof_chars: present.presentation.length,
          prove_ms: Math.round(proveMs),
          verify_ms: Math.round(verifyMs),
          tampered_challenge_rejected: true,
        }));
      } finally {
        await scoped.close();
        rmSync(tempRoot, { recursive: true, force: true });
      }
    },
  );

  it("present requires holder signing material until callback signing is wired", async () => {
    const { env, artifactRoot, keysRoot } = fakeArtifactEnv();
    const scoped = new ProviderProcess(env);
    try {
      const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
      const prepared = assertOk(await scoped.call("prepare", preparePayload(fixture)));
      const payload = swiyuLifecyclePayload(fixture);
      const res = await scoped.call("present", {
        profile: PROFILE,
        handle: prepared.handle,
        request_context: payload.challenge,
        inputs: {
          statusSnapshot: payload.presentInputs.statusSnapshot,
          statusWitness: payload.presentInputs.statusWitness,
        },
      });
      assert.equal(res.status, "error");
      assert.equal(res.error.code, "bad_inputs");
      assert.match(res.error.message, /holderPrivateKeyHex/);
    } finally {
      await scoped.close();
      rmSync(artifactRoot, { recursive: true, force: true });
      rmSync(keysRoot, { recursive: true, force: true });
    }
  });

  it("explicit env paths surface available_files without external fallback", async () => {
    const { env, artifactRoot, keysRoot } = fakeArtifactEnv();
    const scoped = new ProviderProcess(env);
    const init = assertOk(await scoped.call("initialize", {}));
    assert.equal(init.artifacts.available, true);
    assert.equal(init.artifacts.available_files.witnessWasm.present, true);
    assert.equal(init.artifacts.available_files.nativeBinary.present, true);
    assert.deepEqual(init.artifacts.missing, []);
    assert.equal(init.artifacts.files, undefined);
    await scoped.close();
    rmSync(artifactRoot, { recursive: true, force: true });
    rmSync(keysRoot, { recursive: true, force: true });
  });

  it("rejects unknown operation", async () => {
    const res = await client.call("rotate", {});
    assert.equal(res.status, "unsupported");
    assert.equal(res.error.code, "unknown_operation");
  });

  it("binds response id to request id", async () => {
    const id = "test-req-id-12345";
    const res = await client.call("initialize", {}, id);
    assert.equal(res.id, id);
  });

  it("rejects empty request id", async () => {
    const res = await client.call("initialize", {}, "");
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "bad_request");
  });

  it("rejects non-object payload", async () => {
    const client2 = new ProviderProcess();
    const id = "payload-shape";
    const res = await new Promise((resolve) => {
      client2.rl.once("line", (line) => resolve(JSON.parse(line)));
      client2.proc.stdin.write(
        `${JSON.stringify({
          protocol: PROTOCOL,
          id,
          operation: "prepare",
          payload: "not-an-object",
        })}\n`,
      );
    });
    assert.equal(res.error.code, "bad_request");
    await client2.close();
  });

  it("cleanup clears handles after prepare failure path", async () => {
    const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
    const prep = assertOk(await client.call("prepare", preparePayload(fixture)));
    assertOk(await client.call("cleanup", {}));
    const res = await client.call("present", {
      profile: PROFILE,
      handle: prep.handle,
      request_context: {},
      inputs: {},
    });
    assert.equal(res.error.code, "bad_handle");
  });
});

describe("openac provider framing", () => {
  it("malformed JSON yields error response", async () => {
    const client = new ProviderProcess();
    const line = await new Promise((resolve) => {
      client.rl.once("line", resolve);
      client.proc.stdin.write("{not json\n");
    });
    const parsed = JSON.parse(line);
    assert.equal(parsed.status, "error");
    assert.equal(parsed.error.code, "malformed_request");
    await client.close();
  });

  it("wrong protocol version is rejected", async () => {
    const client = new ProviderProcess();
    const id = "proto-check";
    const res = await new Promise((resolve) => {
      client.rl.once("line", (line) => resolve(JSON.parse(line)));
      client.proc.stdin.write(
        `${JSON.stringify({
          protocol: "swiyu.provider.v0",
          id,
          operation: "initialize",
          payload: {},
        })}\n`,
      );
    });
    assert.equal(res.id, id);
    assert.equal(res.status, "error");
    assert.equal(res.error.code, "bad_protocol");
    await client.close();
  });
});

describe("openac quickstart", () => {
  it("writes report to chosen --output directory", async () => {
    const outDir = mkdtempSync(join(tmpdir(), "openac-qs-"));
    const quickstart = join(providerDir(), "quickstart.mjs");
    await new Promise((resolve, reject) => {
      const proc = spawn(process.execPath, [quickstart, "--output", outDir], {
        cwd: providerDir(),
        stdio: ["ignore", "pipe", "pipe"],
      });
      let stderr = "";
      proc.stderr.on("data", (chunk) => {
        stderr += chunk;
      });
      proc.on("close", (code) => {
        if (code === 0) {
          resolve();
        } else {
          reject(new Error(`quickstart exit ${code}: ${stderr}`));
        }
      });
    });
    assert.ok(existsSync(join(outDir, "quickstart-report.json")));
    const report = JSON.parse(readFileSync(join(outDir, "quickstart-report.json"), "utf8"));
    assert.equal(report.proving.status, "absent");
    assert.ok(report.elapsedMs.host.initialize >= 0);
    assert.ok(report.elapsedMs.host.prepare >= 0);
    assert.equal(report.outputDir, outDir);
    rmSync(outDir, { recursive: true, force: true });
  });
});
