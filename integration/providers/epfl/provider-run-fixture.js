#!/usr/bin/env node
"use strict";
const fs = require("fs");
const path = require("path");

function parseU8Array(src, key) {
  const re = new RegExp("^" + key + " = \\[([^\\]]+)\\]", "m");
  const m = src.match(re);
  if (!m) throw new Error("missing " + key);
  const vals = m[1].split(",").map((s) => Number(s.trim()));
  if (vals.length !== 32 || vals.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) {
    throw new Error("bad " + key);
  }
  return vals;
}

function parseU32(src, key) {
  const re = new RegExp("^" + key + " = (\\d+)", "m");
  const m = src.match(re);
  if (!m) throw new Error("missing " + key);
  return Number(m[1]);
}

const explicit = process.env.SWIYU_EPFL_D10_PROVER_TOML;
const sourceRoot = process.env.SWIYU_EPFL_SOURCE_ROOT;
const proverPath = explicit
  ? path.resolve(explicit)
  : sourceRoot
    ? path.resolve(sourceRoot, "noir/d10_swiyu_jwt/Prover.toml")
    : null;
if (!proverPath || !fs.existsSync(proverPath)) {
  process.stderr.write(
    "SWIYU_EPFL_SOURCE_ROOT/noir/d10_swiyu_jwt/Prover.toml or SWIYU_EPFL_D10_PROVER_TOML required\n"
  );
  process.exit(1);
}
const src = fs.readFileSync(proverPath, "utf8");
const issuer_pub_x = parseU8Array(src, "issuer_pub_x");
const issuer_pub_y = parseU8Array(src, "issuer_pub_y");
const now_date = parseU32(src, "now_date");
const challenge_nonce = parseU8Array(src, "challenge_nonce");
const profile = "epfl-d10-swiyu-jwt-age25-v0";
const ctx = { issuer_pub_x, issuer_pub_y, now_date, challenge_nonce };
const wrongNonce = challenge_nonce.slice();
wrongNonce[0] = (wrongNonce[0] + 1) % 256;
const fixture = {
  schema: "swiyu.provider-run-fixture.v1",
  profile,
  case_name: "epfl_d10_native_proof_lifecycle",
  prepare: {
    profile,
    credential: { format: "epfl-d10-prover-toml", path: proverPath },
    context: {},
  },
  present: { profile, request_context: ctx, inputs: {} },
  verify: { profile, request_context: ctx, inputs: {} },
  negative_verify: {
    name: "wrong_challenge_nonce",
    payload: {
      profile,
      request_context: { ...ctx, challenge_nonce: wrongNonce },
      inputs: {},
    },
    expected_verified: false,
  },
};
process.stdout.write(JSON.stringify(fixture));
