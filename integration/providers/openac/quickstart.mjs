#!/usr/bin/env node
/** Local diagnostics: initialize + prepare with synthetic fixture. */
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { ProviderProcess, assertOk } from "./tests/harness.mjs";
import { buildCredentialFixture } from "./tests/fixture.mjs";
import { PROFILE, artifactPaths } from "./paths.mjs";

const PROVIDER_DIR = fileURLToPath(new URL(".", import.meta.url));
const DEFAULT_OUT = resolve(artifactPaths().repoRoot, "artifacts/platform-openac");

function parseArgs(argv) {
  let outputDir = DEFAULT_OUT;
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--output" && argv[i + 1]) {
      outputDir = resolve(argv[i + 1]);
      i += 1;
    }
  }
  return { outputDir };
}

const { outputDir } = parseArgs(process.argv.slice(2));
mkdirSync(outputDir, { recursive: true });

const client = new ProviderProcess();
const hostElapsedMs = {};
let report;

try {
  const t0 = performance.now();
  const init = assertOk(await client.call("initialize", {}));
  hostElapsedMs.initialize = performance.now() - t0;

  const t1 = performance.now();
  const fixture = buildCredentialFixture({ swiyuIssuerShape: true });
  const prep = assertOk(
    await client.call("prepare", {
      profile: PROFILE,
      credential: { format: "dc+sd-jwt", data: fixture.compactSdJwt },
      context: { issuerPublicKey: fixture.issuerPublicKey },
    }),
  );
  hostElapsedMs.prepare = performance.now() - t1;

  report = {
    profile: PROFILE,
    targetProfile: PROFILE,
    preparation: {
      initialize: {
        operationReadiness: init.operationReadiness,
        artifacts: init.artifacts,
      },
      prepare: prep,
    },
    proving: { status: "absent", note: "adapter does not emit ZK proofs" },
    elapsedMs: { host: hostElapsedMs },
    outputDir,
  };

  writeFileSync(join(outputDir, "quickstart-report.json"), JSON.stringify(report, null, 2));
  writeFileSync(
    join(outputDir, "example-request.jsonl"),
    [
      JSON.stringify({
        protocol: "swiyu.provider.v1",
        id: "example-1",
        operation: "initialize",
        payload: {},
      }),
      JSON.stringify({
        protocol: "swiyu.provider.v1",
        id: "example-2",
        operation: "prepare",
        payload: {
          profile: PROFILE,
          credential: { format: "dc+sd-jwt", data: "<synthetic compact SD-JWT>" },
          context: { issuerPublicKey: fixture.issuerPublicKey },
        },
      }),
    ].join("\n") + "\n",
  );

  console.log(JSON.stringify(report, null, 2));
} finally {
  try {
    await client.call("cleanup", {});
  } catch {
    /* ignore */
  }
  await client.close();
}
