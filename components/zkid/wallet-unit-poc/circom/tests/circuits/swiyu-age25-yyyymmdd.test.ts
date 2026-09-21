import assert from "node:assert/strict";
import type { WitnessTester } from "circomkit";

import { circomkit } from "../common/index.ts";

describe("shared age-25 YYYYMMDD gate", function () {
  this.timeout(120_000);

  let circuit: WitnessTester<["birthdateNumeric", "nowDate"], ["ok"]>;

  before(async () => {
    circuit = await circomkit.WitnessTester("YyyymmddAgeAtLeastCheck", {
      file: "swiyu/yyyymmdd-age",
      template: "YyyymmddAgeAtLeastCheck",
      params: [25],
      recompile: true,
    });
  });

  it("accepts the 25th birthday (EPFL d10 rule)", async () => {
    const witness = await circuit.calculateWitness({
      birthdateNumeric: 19_880_619n,
      nowDate: 20_130_619n,
    });
    await circuit.expectConstraintPass(witness);
    const { ok } = await circuit.readWitnessSignals(witness, ["ok"]);
    assert.equal(ok, 1n);
  });

  it("rejects the day before the 25th birthday", async () => {
    const witness = await circuit.calculateWitness({
      birthdateNumeric: 19_880_619n,
      nowDate: 20_130_618n,
    });
    await circuit.expectConstraintPass(witness);
    const { ok } = await circuit.readWitnessSignals(witness, ["ok"]);
    assert.equal(ok, 0n);
  });

  it("accepts a later adult date used by the shared claim corpus", async () => {
    const witness = await circuit.calculateWitness({
      birthdateNumeric: 19_880_619n,
      nowDate: 20_240_101n,
    });
    await circuit.expectConstraintPass(witness);
    const { ok } = await circuit.readWitnessSignals(witness, ["ok"]);
    assert.equal(ok, 1n);
  });
});
