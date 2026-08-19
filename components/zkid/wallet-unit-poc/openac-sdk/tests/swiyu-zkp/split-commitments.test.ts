import { describe, expect, it } from "vitest";
import { hashSwiyuChallenge } from "../../src/swiyu-zkp/challenge.js";
import {
  computeSwiyuPreparedLookupCommitment,
  computeSwiyuPreparedSessionCommitment,
  computeSwiyuPreparedStatusCommitment,
  computeSwiyuPreparedStatusUriCommitment,
} from "../../src/swiyu-zkp/commitments.js";
import { buildCredentialFixture, makeChallenge, makeStatus } from "./fixture.js";

describe("Prepare/Show commitment vectors", () => {
  it("matches the constrained benchmark fixture", () => {
    const credential = buildCredentialFixture({ swiyuIssuerShape: true });
    const lookup = computeSwiyuPreparedLookupCommitment({
      issuer: "did:example:issuer",
      kid: credential.issuerPublicKey.kid!,
      vct: "https://example.ch/vct/person",
    });
    const uri = computeSwiyuPreparedStatusUriCommitment(credential.statusUri);
    const challenge = hashSwiyuChallenge(makeChallenge()).scalar;
    const statusRoot = makeStatus().snapshot.root;

    expect(lookup).toEqual({
      hashHi: 337616652340616765709413123571994562837n,
      hashLo: 259140651913422432570676909175008620912n,
    });
    expect(uri).toEqual({
      hashHi: 45567781746925399912114589800924482042n,
      hashLo: 195967405013153578449867865253054386113n,
    });
    expect(computeSwiyuPreparedSessionCommitment(challenge, lookup)).toEqual({
      hashHi: 313927688688669177223052119079645262283n,
      hashLo: 338052470328626775642301851615909487025n,
    });
    expect(computeSwiyuPreparedStatusCommitment(uri, statusRoot)).toEqual({
      hashHi: 209799587954403568442386823119399521719n,
      hashLo: 319442307260500777320950761878611188998n,
    });
  });
});
