import { describe, expect, it } from "vitest";
import { WasmSwiyuProofBackend } from "../../src/swiyu-zkp/backend.js";

const publicValues = () =>
  Array.from({ length: 10 }, (_, index) => {
    const scalar = new Uint8Array(32);
    scalar[0] = index;
    return scalar;
  });

describe("typed swiyu WASM proof boundary", () => {
  it("adapts real prove/verify export shapes and copies returned bytes", async () => {
    const bindings = {
      swiyu_prove_from_witness: () => ({
        proof: new Uint8Array([5, 6]),
        public_values: publicValues(),
      }),
      swiyu_verify: () => ({
        valid: true,
        public_values: publicValues(),
        error: null,
      }),
    };
    const backend = new WasmSwiyuProofBackend(bindings);
    await expect(
      backend.proveFromWitness(new Uint8Array([1]), new Uint8Array([2])),
    ).resolves.toMatchObject({ proof: new Uint8Array([5, 6]) });
    await expect(
      backend.verify(
        new Uint8Array([5]),
        new Uint8Array([3]),
        new Uint8Array(320),
      ),
    ).resolves.toMatchObject({ valid: true, publicValues: publicValues() });
  });

  it("preserves fail-closed verification results with no public values", async () => {
    const backend = new WasmSwiyuProofBackend({
      swiyu_prove_from_witness: () => ({
        proof: new Uint8Array([1]),
        public_values: publicValues(),
      }),
      swiyu_verify: () => ({
        valid: false,
        public_values: [],
        error: "proof public context mismatch",
      }),
    });
    await expect(
      backend.verify(
        new Uint8Array([1]),
        new Uint8Array([2]),
        new Uint8Array(320),
      ),
    ).resolves.toEqual({
      valid: false,
      publicValues: [],
      error: "proof public context mismatch",
    });
  });

  it("rejects obsolete nine-value prover output", async () => {
    const backend = new WasmSwiyuProofBackend({
      swiyu_prove_from_witness: () => ({
        proof: new Uint8Array([1]),
        public_values: publicValues().slice(0, 9),
      }),
      swiyu_verify: () => ({
        valid: false,
        public_values: [],
        error: null,
      }),
    });
    await expect(
      backend.proveFromWitness(new Uint8Array([1]), new Uint8Array([2])),
    ).rejects.toThrow(/exactly ten public values/);
  });

  it("rejects local-file keys at the WASM boundary", async () => {
    const backend = new WasmSwiyuProofBackend({
      swiyu_prove_from_witness: () => {
        throw new Error("binding must not be called");
      },
      swiyu_verify: () => {
        throw new Error("binding must not be called");
      },
    });
    const localKey = { kind: "local-file" as const, path: "/tmp/swiyu.key" };

    await expect(
      backend.proveFromWitness(localKey, new Uint8Array([1])),
    ).rejects.toThrow(/local-file keys require the Node native backend/);
    await expect(
      backend.verify(new Uint8Array([1]), localKey, new Uint8Array(320)),
    ).rejects.toThrow(/local-file keys require the Node native backend/);
  });
});
