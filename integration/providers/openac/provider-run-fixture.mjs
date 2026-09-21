#!/usr/bin/env node
import { PROFILE } from "./paths.mjs";
import {
  buildCredentialFixture,
  makeChallenge,
  makeStatus,
} from "./tests/fixture.mjs";

const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
const { snapshot, authoritativeSnapshot, witness } = makeStatus(fixture.statusIndex);
const challenge = makeChallenge(snapshot.id);

const document = {
  schema: "swiyu.provider-run-fixture.v1",
  profile: PROFILE,
  case_name: "openac_real_proof_lifecycle",
  prepare: {
    profile: PROFILE,
    credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
    context: { issuerPublicKey: fixture.issuerPublicKey },
  },
  present: {
    profile: PROFILE,
    request_context: challenge,
    inputs: {
      holderPrivateKeyHex: fixture.holderPrivateKeyHex,
      statusSnapshot: snapshot,
      statusWitness: witness,
    },
  },
  verify: {
    profile: PROFILE,
    request_context: challenge,
    inputs: {
      issuerPublicKey: fixture.issuerPublicKey,
      statusSnapshot: authoritativeSnapshot,
    },
  },
  negative_verify: {
    name: "tampered_challenge",
    payload: {
      profile: PROFILE,
      request_context: { ...challenge, nonce: `${challenge.nonce}-bad` },
      inputs: {
        issuerPublicKey: fixture.issuerPublicKey,
        statusSnapshot: authoritativeSnapshot,
      },
    },
    expected_verified: false,
  },
};

process.stdout.write(`${JSON.stringify(document)}\n`);
