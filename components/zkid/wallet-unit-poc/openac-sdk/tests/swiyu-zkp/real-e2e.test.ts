import { stat, writeFile } from "fs/promises";
import { join, resolve } from "path";
import { performance } from "perf_hooks";
import { describe, expect, it } from "vitest";
import { WitnessCalculator } from "../../src/witness-calculator.js";
import { NativeNodeSwiyuProofBackend } from "../../src/swiyu-zkp/native-backend-node.js";
import { SwiyuVerifierSidecarService } from "../../src/swiyu-zkp/sidecar.js";
import { SwiyuZkpVerifier, SwiyuZkpWallet } from "../../src/swiyu-zkp/wallet.js";
import {
  BindingTestBackend,
  RecordingWitnessGenerator,
  buildCredentialFixture,
  holderSigner,
  makeChallenge,
  makeStatus,
} from "./fixture.js";

const mode = process.env.SWIYU_REAL_E2E_MODE;
const witnessTest = mode === "witness" || mode === "proof" ? it : it.skip;
const proofTest = mode === "proof" ? it : it.skip;
let generatedWitnessPromise: ReturnType<typeof calculateRealWitness> | undefined;

describe("real swiyu fixed-profile artifacts", () => {
  witnessTest(
    "generates the final Circom witness from an issuer-shaped SD-JWT",
    async () => {
      const generated = await generateRealWitness();
      expect(generated.wtns.byteLength).toBeGreaterThan(1_000_000);
      expect(generated.inputs.currentTime).toBe(makeChallenge().currentTime);

      const output = process.env.SWIYU_WTNS_OUTPUT;
      if (output) await writeFile(output, generated.wtns);
      console.log(
        JSON.stringify({
          phase: "witness",
          witness_bytes: generated.wtns.byteLength,
          witness_ms: Math.round(generated.witnessMs),
          output: output ?? null,
        }),
      );
    },
    20 * 60_000,
  );

  proofTest(
    "proves and verifies one session-bound presentation with provisioned keys",
    async () => {
      const generated = await generateRealWitness();
      const profileCwd = resolve(
        process.env.SWIYU_PROFILE_CWD ?? join("..", "ecdsa-spartan2"),
      );
      const keyDirectory = resolve(
        process.env.SWIYU_KEYS_DIR ?? join(profileCwd, "keys"),
      );
      const provingKeyPath = join(
        keyDirectory,
        "swiyu_age18_status_2k_proving.key",
      );
      const verifyingKeyPath = join(
        keyDirectory,
        "swiyu_age18_status_2k_verifying.key",
      );
      const [provingKey, verifyingKey] = await Promise.all([
        stat(provingKeyPath),
        stat(verifyingKeyPath),
      ]);

      const backend = new NativeNodeSwiyuProofBackend({
        binaryPath: resolve(
          process.env.SWIYU_PROFILE_BIN ??
            join(profileCwd, "target", "release", "swiyu-profile"),
        ),
        cwd: profileCwd,
      });
      const witnessGenerator = {
        async calculateSwiyuWitnessWtns() {
          return generated.wtns;
        },
      };
      const wallet = new SwiyuZkpWallet({ witnessGenerator, proofBackend: backend });
      const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
      const prepared = wallet.prepare({
        compactSdJwt: fixture.compactSdJwt,
        issuerPublicKey: fixture.issuerPublicKey,
      });
      const challenge = makeChallenge();
      const { snapshot, authoritativeSnapshot, witness } = makeStatus();

      const proveStarted = performance.now();
      const envelope = await wallet.show({
        prepared,
        challenge,
        holderSigner: holderSigner(),
        statusSnapshot: snapshot,
        statusWitness: witness,
        provingKey: { kind: "local-file", path: provingKeyPath },
      });
      const proveMs = performance.now() - proveStarted;

      const verifier = new SwiyuZkpVerifier(backend);
      const verifyStarted = performance.now();
      const verified = await verifier.verify({
        envelope,
        challenge,
        issuerPublicKey: fixture.issuerPublicKey,
        statusSnapshot: authoritativeSnapshot,
        verifyingKey: { kind: "local-file", path: verifyingKeyPath },
      });
      const verifyMs = performance.now() - verifyStarted;
      expect(verified).toEqual({ valid: true });

      const tampered = await verifier.verify({
        envelope,
        challenge: { ...challenge, nonce: `${challenge.nonce}-tampered` },
        issuerPublicKey: fixture.issuerPublicKey,
        statusSnapshot: authoritativeSnapshot,
        verifyingKey: { kind: "local-file", path: verifyingKeyPath },
      });
      expect(tampered.valid).toBe(false);

      const sidecar = new SwiyuVerifierSidecarService({
        verifier,
        verifyingKey: { kind: "local-file", path: verifyingKeyPath },
        issuers: [{
          issuer: envelope.lookup.issuer,
          kid: envelope.lookup.kid,
          publicKey: fixture.issuerPublicKey,
          vctValues: [envelope.lookup.vct],
          trustAnchors: [],
        }],
        statusSnapshots: [authoritativeSnapshot],
      });
      const sidecarResult = await sidecar.verifyJson(JSON.stringify({
        proof_envelope: JSON.stringify(envelope),
        expected: {
          nonce: challenge.nonce,
          client_id: challenge.clientId,
          response_uri: challenge.responseUri,
          state: challenge.state,
          query_id: challenge.queryId,
          profile: envelope.profile,
          circuit_id: envelope.circuitId,
          cutoff_date: challenge.cutoffDate,
          current_time: Number(challenge.currentTime),
          status_list_snapshot: challenge.statusListSnapshot,
          vct_values: [envelope.lookup.vct],
          accepted_issuer_dids: [envelope.lookup.issuer],
          trust_anchors: [],
        },
      }));
      expect(sidecarResult).toEqual({
        verified: true,
        profile: envelope.profile,
        circuit_id: envelope.circuitId,
        predicate_satisfied: true,
        status_valid: true,
        status_list_snapshot: challenge.statusListSnapshot,
      });

      expect(Object.keys(envelope).sort()).toEqual([
        "circuitId",
        "lookup",
        "profile",
        "proof",
        "version",
      ]);
      expect(Object.keys(envelope.lookup).sort()).toEqual(["issuer", "kid", "vct"]);
      // The proof is an opaque randomized byte string, so substring searches
      // inside its base64url representation are meaningless. Inspect only the
      // structured envelope surface when asserting non-disclosure.
      const observableEnvelope = JSON.stringify({ ...envelope, proof: "<opaque>" });
      expect(observableEnvelope).not.toContain("birthdate");
      expect(observableEnvelope).not.toContain(snapshot.uri);
      expect(observableEnvelope).not.toContain("statusIndex");
      console.log(
        JSON.stringify({
          phase: "proof",
          backend: "native-node",
          proving_key_bytes: provingKey.size,
          verifying_key_bytes: verifyingKey.size,
          proof_base64url_bytes: envelope.proof.length,
          prove_ms: Math.round(proveMs),
          verify_ms: Math.round(verifyMs),
          verified: verified.valid,
          tampered_challenge_rejected: !tampered.valid,
          sidecar_contract_verified: sidecarResult.verified,
        }),
      );
    },
    30 * 60_000,
  );
});

async function generateRealWitness() {
  generatedWitnessPromise ??= calculateRealWitness();
  return generatedWitnessPromise;
}

async function calculateRealWitness() {
  const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
  const challenge = makeChallenge();
  const { snapshot, witness } = makeStatus();
  const recorder = new RecordingWitnessGenerator();
  const bindingWallet = new SwiyuZkpWallet({
    witnessGenerator: recorder,
    proofBackend: new BindingTestBackend(recorder),
  });
  const prepared = bindingWallet.prepare({
    compactSdJwt: fixture.compactSdJwt,
    issuerPublicKey: fixture.issuerPublicKey,
  });
  await bindingWallet.show({
    prepared,
    challenge,
    holderSigner: holderSigner(),
    statusSnapshot: snapshot,
    statusWitness: witness,
    provingKey: new Uint8Array([1]),
  });
  if (!recorder.inputs) throw new Error("fixture did not produce circuit inputs");

  const calculator = new WitnessCalculator(join(process.cwd(), "assets"));
  await calculator.init();
  const started = performance.now();
  const wtns = await calculator.calculateSwiyuWitnessWtns(recorder.inputs);
  return {
    inputs: recorder.inputs,
    wtns,
    witnessMs: performance.now() - started,
  };
}
