import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { WitnessTester } from "circomkit";
import { p256 } from "@noble/curves/nist.js";

import { circomkit } from "../common/index.ts";

const Q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const inverse = (value: bigint): bigint => {
  let a = ((value % Q) + Q) % Q;
  let b = Q;
  let x = 1n;
  let y = 0n;
  while (b !== 0n) {
    const quotient = a / b;
    [a, b] = [b, a - quotient * b];
    [x, y] = [y, x - quotient * y];
  }
  return (x + Q) % Q;
};

describe("P-256 ECDSA scalar-bit reuse", function () {
  this.timeout(900_000);

  it("verifies a real signature after sharing the constrained s-inverse bits", async () => {
    const circuit: WitnessTester<
      ["s_inverse", "r", "m", "pubKeyX", "pubKeyY"],
      []
    > = await circomkit.WitnessTester("ECDSA", {
      file: "ecdsa/ecdsa",
      template: "ECDSA",
      params: [],
      recompile: true,
    });
    const privateKey = 0x123456789abcdef123456789abcdefn;
    const digest = createHash("sha256").update("swiyu-ecdsa-reuse").digest();
    const signature = p256.sign(digest, privateKey);
    const point = p256.ProjectivePoint.fromPrivateKey(privateKey).toAffine();
    const message = BigInt(`0x${digest.toString("hex")}`);
    const witness = await circuit.calculateWitness({
      s_inverse: inverse(signature.s),
      r: signature.r,
      m: message,
      pubKeyX: point.x,
      pubKeyY: point.y,
    });
    await circuit.expectConstraintPass(witness);
    assert.ok(witness.length > 1);
  });
});
