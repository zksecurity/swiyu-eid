import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

describe("K_add", () => {
  let circuit!: WitnessTester<["s"], ["out"]>;

  const q = BigInt("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");

  before(async () => {
    circuit = await circomkit.WitnessTester("KAddBinding", {
      file: "ecdsa/p256/mul",
      template: "K_add",
      params: [],
      recompile: true,
    });
  });

  it("accepts canonical secp256r1 scalars", async () => {
    await circuit.expectPass({ s: 0n });
    await circuit.expectPass({ s: 1n });
    await circuit.expectPass({ s: q - 1n });
  });

  it("rejects the non-canonical scalar-field order", async () => {
    await circuit.expectFail({ s: q });
  });

  it("binds the split limbs to the supplied scalar", async () => {
    const claimedScalar = 1n;
    const substitutedScalar = 2n;
    const substitutedWitness = await circuit.calculateWitness({ s: substitutedScalar });

    // Model a dishonest prover: keep the decomposition and all derived bits
    // for s=2, but change the circuit input to s=1. This was satisfiable while
    // slo/shi were unconstrained hints.
    const forgedWitness = await circuit.editWitness(substitutedWitness, {
      "main.s": claimedScalar,
    });
    await circuit.expectConstraintFail(forgedWitness);
  });
});
