import assert from "node:assert/strict";
import type { WitnessTester } from "circomkit";
import { circomkit } from "../common/index.ts";

describe("Secp256r1AddComplete", () => {
  let circuit!: WitnessTester<["xP", "yP", "xQ", "yQ"], ["outX", "outY"]>;

  const p = BigInt("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
  const gx = BigInt("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
  const gy = BigInt("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");

  before(async () => {
    circuit = await circomkit.WitnessTester("P256CompleteAddRegression", {
      file: "ecdsa/p256/add",
      template: "Secp256r1AddComplete",
      params: [],
      recompile: true,
    });
  });

  it("maps a point plus its inverse to the infinity sentinel", async () => {
    await circuit.expectPass(
      { xP: gx, yP: gy, xQ: gx, yQ: p - gy },
      { outX: 0n, outY: 0n },
    );
  });

  it("does not zeroize unrelated points whose y coordinates sum to one", async () => {
    const witness = await circuit.calculateWitness({ xP: 2n, yP: 3n, xQ: 4n, yQ: p - 2n });
    await circuit.expectConstraintPass(witness);
    const { outX, outY } = await circuit.readWitnessSignals(witness, ["outX", "outY"]);
    assert.notDeepEqual([outX, outY], [0n, 0n]);
  });

  it("binds the inactive addition slope to zero in the doubling branch", async () => {
    const witness = await circuit.calculateWitness({ xP: gx, yP: gy, xQ: gx, yQ: gy });
    const { "main.lambdaB": lambdaB } = await circuit.readWitness(witness, ["main.lambdaB"]);
    const lambda = mod(lambdaB + 1n);
    const outX = mod(lambda * lambda - 2n * gx);
    const outY = mod(lambda * (gx - outX) - gy);
    const forgedWitness = await circuit.editWitness(witness, {
      "main.lambdaA": 1n,
      "main.lambda": lambda,
      "main.outAx": outX,
      "main.outAy": outY,
      "main.outBx": outX,
      "main.outBy": outY,
      "main.outX": outX,
      "main.outY": outY,
    });
    await circuit.expectConstraintFail(forgedWitness);
  });

  function mod(value: bigint): bigint {
    const reduced = value % p;
    return reduced < 0n ? reduced + p : reduced;
  }
});
