import type {
  SwiyuBackendVerification,
  SwiyuKeyMaterial,
  SwiyuProofBackend,
  SwiyuProveResult,
} from "./types.js";

export interface SwiyuWasmBindings {
  swiyu_prove_from_witness(
    provingKey: Uint8Array,
    witness: Uint8Array,
  ):
    | {
        proof: Uint8Array;
        public_values: readonly Uint8Array[];
      }
    | Promise<{
        proof: Uint8Array;
        public_values: readonly Uint8Array[];
      }>;
  swiyu_verify(
    proof: Uint8Array,
    verifyingKey: Uint8Array,
    expectedPublicContext: Uint8Array,
  ):
    | {
        valid: boolean;
        public_values: readonly Uint8Array[];
        error?: string | null;
      }
    | Promise<{
        valid: boolean;
        public_values: readonly Uint8Array[];
        error?: string | null;
      }>;
}

export interface SwiyuBridgeBindings {
  swiyuProveFromWitness(
    provingKey: Uint8Array,
    witness: Uint8Array,
  ): Promise<{ proof: Uint8Array; publicValues: readonly Uint8Array[] }>;
  swiyuVerify(
    proof: Uint8Array,
    verifyingKey: Uint8Array,
    expectedPublicContext: Uint8Array,
  ): Promise<{
    valid: boolean;
    publicValues: readonly Uint8Array[];
    error?: string;
  }>;
}

/** Thin typed adapter over the real single-proof Spartan WASM exports. */
export class WasmSwiyuProofBackend implements SwiyuProofBackend {
  constructor(private readonly bindings: SwiyuWasmBindings) {}

  async proveFromWitness(
    provingKey: SwiyuKeyMaterial,
    witness: Uint8Array,
  ): Promise<SwiyuProveResult> {
    const result = await this.bindings.swiyu_prove_from_witness(
      requireByteKey(provingKey, "proving key"),
      witness,
    );
    return {
      proof: copyBytes(result.proof, "proof"),
      publicValues: normalizePublicValues(result.public_values),
    };
  }

  async verify(
    proof: Uint8Array,
    verifyingKey: SwiyuKeyMaterial,
    expectedPublicContext: Uint8Array,
  ): Promise<SwiyuBackendVerification> {
    const result = await this.bindings.swiyu_verify(
      proof,
      requireByteKey(verifyingKey, "verifying key"),
      expectedPublicContext,
    );
    return {
      valid: result.valid === true,
      publicValues: result.valid ? normalizePublicValues(result.public_values) : [],
      error: result.error ?? undefined,
    };
  }
}

/** Adapter for the SDK's initialized `WasmBridge`. */
export class WasmBridgeSwiyuProofBackend implements SwiyuProofBackend {
  constructor(private readonly bridge: SwiyuBridgeBindings) {}

  async proveFromWitness(
    provingKey: SwiyuKeyMaterial,
    witness: Uint8Array,
  ): Promise<SwiyuProveResult> {
    const result = await this.bridge.swiyuProveFromWitness(
      requireByteKey(provingKey, "proving key"),
      witness,
    );
    return {
      proof: copyBytes(result.proof, "proof"),
      publicValues: normalizePublicValues(result.publicValues),
    };
  }

  async verify(
    proof: Uint8Array,
    verifyingKey: SwiyuKeyMaterial,
    expectedPublicContext: Uint8Array,
  ): Promise<SwiyuBackendVerification> {
    const result = await this.bridge.swiyuVerify(
      proof,
      requireByteKey(verifyingKey, "verifying key"),
      expectedPublicContext,
    );
    return {
      valid: result.valid,
      publicValues: result.valid ? normalizePublicValues(result.publicValues) : [],
      error: result.error,
    };
  }
}

function requireByteKey(key: SwiyuKeyMaterial, label: string): Uint8Array {
  if (!(key instanceof Uint8Array) || key.length === 0) {
    throw new Error(
      `swiyu WASM ${label} must be a non-empty Uint8Array; local-file keys require the Node native backend`,
    );
  }
  return key;
}

function normalizePublicValues(values: readonly Uint8Array[]): Uint8Array[] {
  if (!Array.isArray(values) || values.length !== 10) {
    throw new Error("swiyu proof backend must return exactly ten public values");
  }
  return values.map((value, index) => copyScalar(value, index));
}

function copyScalar(value: Uint8Array, index: number): Uint8Array {
  const copy = copyBytes(value, `public value ${index}`);
  if (copy.length !== 32) {
    throw new Error(`public value ${index} must contain exactly 32 bytes`);
  }
  return copy;
}

function copyBytes(value: Uint8Array, label: string): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw new Error(`${label} is not a Uint8Array`);
  }
  return new Uint8Array(value);
}
