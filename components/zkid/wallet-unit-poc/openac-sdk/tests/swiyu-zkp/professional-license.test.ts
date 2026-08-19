import { describe, expect, it } from "vitest";
import {
  SWIYU_PROFESSIONAL_LICENSE_VCT,
  buildProfessionalLicensePublicContext,
} from "../../src/swiyu-zkp/professional-license.js";
import { buildCredentialFixture, makeStatus } from "./fixture.js";
import { parseSwiyuCompactSdJwt } from "../../src/swiyu-zkp/parser.js";

describe("professional-licence verifier policy", () => {
  it("binds the accepted VCT, future service date, challenge, and status root", () => {
    const fixture = buildCredentialFixture({ vct: SWIYU_PROFESSIONAL_LICENSE_VCT });
    const parsed = parseSwiyuCompactSdJwt(
      fixture.compactSdJwt,
      fixture.issuerPublicKey,
    );
    const { snapshot } = makeStatus();
    const context = buildProfessionalLicensePublicContext({
      lookup: parsed.lookup,
      statusUri: parsed.statusUri,
      statusRoot: snapshot.root,
      challengeHash: 123n,
      currentTime: 1_750_000_000n,
      requiredValidUntil: 1_760_000_000n,
    });
    expect(context.requiredValidUntil).toBe(1_760_000_000n);
    expect(context.expectedMetadata.hashHi).toBeGreaterThan(0n);
    expect(context.expectedStatusSnapshot.hashHi).toBeGreaterThan(0n);
  });

  it("rejects a credential outside the verifier's accepted VCT", () => {
    expect(() =>
      buildProfessionalLicensePublicContext({
        lookup: { issuer: "did:example:issuer", kid: "key-1", vct: "person" },
        statusUri: "https://status.example/list",
        statusRoot: "00".repeat(32),
        challengeHash: 123n,
        currentTime: 10n,
        requiredValidUntil: 20n,
      }),
    ).toThrow(/VCT is not accepted/);
  });

  it("requires a strictly future validity horizon", () => {
    expect(() => buildProfessionalLicensePublicContext({
      lookup: {
        issuer: "did:example:issuer",
        kid: "key-1",
        vct: SWIYU_PROFESSIONAL_LICENSE_VCT,
      },
      statusUri: "https://status.example/list",
      statusRoot: "00".repeat(32),
      challengeHash: 123n,
      currentTime: 20n,
      requiredValidUntil: 20n,
    })).toThrow(/strictly after/);
  });
});
