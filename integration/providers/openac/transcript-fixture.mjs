#!/usr/bin/env node
/**
 * OpenAC transcript campaign factory.
 * Emits >=2 variants with the same issuer metadata and different hidden
 * birthdate + statusIndex. Does not claim semantic equivalence.
 */
import { createHash } from "node:crypto";
import { PROFILE } from "./paths.mjs";
import {
  CHECKED_IN_DID_TDW_KID,
  buildCredentialFixture,
  makeChallenge,
  makeStatus,
} from "./tests/fixture.mjs";

const CURRENT_TIME = String(Math.floor(Date.now() / 1000));
const CUTOFF = "2007-06-15";

function givenFor(fixture, status) {
  const challenge = { ...makeChallenge(status.snapshot.id), currentTime: CURRENT_TIME };
  return {
    issuer: {
      public_key: fixture.issuerPublicKey,
      issuer_id: "did:example:issuer",
      key_id: CHECKED_IN_DID_TDW_KID,
      allowed_vcts: ["https://example.ch/vct/person"],
    },
    current_time: CURRENT_TIME,
    age18_cutoff: CUTOFF,
    session: {
      nonce: challenge.nonce,
      client_id: challenge.clientId,
      response_uri: challenge.responseUri,
      state: challenge.state,
      query_id: challenge.queryId,
    },
    status_snapshot: {
      id: status.authoritativeSnapshot.id,
      issuer_id: status.authoritativeSnapshot.issuer,
      key_id: status.authoritativeSnapshot.kid,
      subject: status.authoritativeSnapshot.subject,
      commitment: BigInt(status.authoritativeSnapshot.commitment.hashHi).toString(16).padStart(32, "0") + BigInt(status.authoritativeSnapshot.commitment.hashLo).toString(16).padStart(32, "0"),
      epoch: String(status.authoritativeSnapshot.epoch),
      list_length: status.authoritativeSnapshot.listLength,
      valid_before: status.authoritativeSnapshot.validBefore,
    },
  };
}

function variant(id, options) {
  const fixture = buildCredentialFixture({
    swiyuIssuerShape: true,
    birthdate: options.birthdate,
    statusIndex: options.statusIndex,
  });
  const status = makeStatus(fixture.statusIndex);
  const challenge = { ...makeChallenge(status.snapshot.id), currentTime: CURRENT_TIME };
  const given = givenFor(fixture, status);
  return {
    id,
    credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
    given,
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
        statusSnapshot: status.snapshot,
        statusWitness: status.witness,
      },
    },
    verify: {
      profile: PROFILE,
      request_context: challenge,
      inputs: {
        issuerPublicKey: fixture.issuerPublicKey,
        statusSnapshot: status.authoritativeSnapshot,
      },
    },
    compact_sd_jwt_sha256: createHash("sha256").update(fixture.compactSdJwt).digest("hex"),
  };
}

const document = {
  schema: "swiyu.transcript-fixture.v1",
  equivalence: "not_claimed",
  mapping: {
    format: "dc+sd-jwt",
    profile: PROFILE,
    query_id: "age-over-18-and-valid-status",
    challenge_from: "present.request_context",
    givens: {
      issuer: "issuer",
      current_time: "current_time",
      cutoff: "age18_cutoff",
      session: "session",
      status: "status_snapshot",
    },
    challenge_fields: {nonce: "nonce", clientId: "client_id", responseUri: "response_uri", state: "state"},
    signature_opaque: true,
  },
  dcql_query: { credentials: [{
    id: "age-over-18-and-valid-status", format: "dc+sd-jwt",
    meta: {vct_values: ["https://example.ch/vct/person"]},
    require_cryptographic_holder_binding: true,
    claims: [{id: "birthdate", path: ["birthdate"]}],
    x_swiyu_zkp: {profile: PROFILE, circuit_id: "swiyu_age18_status_2k", cutoff_date: CUTOFF, current_time: Number(CURRENT_TIME), status_list_snapshot: "ch-tsl-2026-07-epoch-172"}
  }]},
  proof_path: "/proof",
  variants: [
    variant("dob-2000-02-29-status-42", {
      birthdate: "2000-02-29",
      statusIndex: 42,
    }),
    variant("dob-1995-12-01-status-7", {
      birthdate: "1995-12-01",
      statusIndex: 7,
    }),
  ],
};

process.stdout.write(`${JSON.stringify(document)}\n`);
