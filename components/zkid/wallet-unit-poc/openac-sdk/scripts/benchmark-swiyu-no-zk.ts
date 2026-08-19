/**
 * Same-host controls for the standard swiyu SD-JWT presentation path.
 *
 * Each raw run executes in a fresh process. Network resolution is excluded:
 * issuer keys, policy material, and status data are preloaded exactly as they
 * are for the ZK benchmark. Stateful scoped-nullifier enforcement is measured
 * by benchmark-swiyu-nullifier-state.mjs and composed by the final aggregate;
 * keeping it separate prevents a 1,000-iteration loop from measuring one
 * successful claim followed by 999 replay failures.
 */
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2";
import {
  SWIYU_BENCHMARK_NULLIFIER_CREDENTIAL_UID_HEX,
  SWIYU_BENCHMARK_NULLIFIER_HOLDER_SECRET_HEX,
  SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS,
} from "../src/swiyu-zkp/nullifier-benchmark-manifest.ts";
import {
  SWIYU_BENCHMARK_RESIDENCE,
  SWIYU_BENCHMARK_RESIDENCE_STATUS,
} from "../src/swiyu-zkp/residence-benchmark-manifest.ts";
import { SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2 } from "../src/swiyu-zkp/status-benchmark-manifest.ts";

type Json = Record<string, any>;
type DisclosureClaim = [string, unknown];

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ISSUER_SECRET = scalar(0x123456789abcdef123456789abcdefn);
const HOLDER_SECRET = scalar(0xabcdef123456789abcdef123456789n);
const NOW = 1_750_000_000;
const CURRENT_EPOCH_DAY = Math.floor(NOW / 86_400);
const NONCE = "n-7f3f778d0be4474e";
const AUDIENCE = "x509_san_dns:verifier.example.ch";
const STATUS_INDEX = 42;
const STATUS_LIST_URI = "https://status.example.ch/lists/2026-07";
const ACCEPTED_PERSON_ISSUER = "did:example:issuer";
const ACCEPTED_RESIDENCE_ISSUER = "did:example:issuer";
const ACCEPTED_PROFESSIONAL_ISSUER = "did:example:licen";
const ACCEPTED_ISSUER_KID = "did:tdw:QmYyQSo1c1Ym7orWxLYvCrzRLZad5ZxQ8HkBLyEE4RRAA1:identifier.admin.ch:api:v1:did#assert-key-01";
const ACCEPTED_PERSON_VCT = "https://example.ch/vct/person";
const ACCEPTED_RESIDENCE_VCT = SWIYU_BENCHMARK_RESIDENCE.vct;
const PROFESSIONAL_REQUIRED_VALID_UNTIL = 1_760_000_000;
const PROFESSIONAL_ACCEPTED_VCT = "urn:ch:professional-license:v1";
const RESIDENCE_POLICY_ID = SWIYU_BENCHMARK_RESIDENCE.policyId;
const RESIDENCE_POLICY_VERSION = SWIYU_BENCHMARK_RESIDENCE.policyVersion;
const RESIDENCE_DIRECTORY_AS_OF = SWIYU_BENCHMARK_RESIDENCE.policy.municipalityDirectoryAsOf;
const RESIDENCE_ALLOWED_MUNICIPALITY_BFS = SWIYU_BENCHMARK_RESIDENCE.policy.allowedMunicipalityBfs;
const RESIDENCE_SELECTED_MUNICIPALITY_BFS = SWIYU_BENCHMARK_RESIDENCE.selectedMunicipalityBfs;
const RESIDENCE_MINIMUM_DAYS = SWIYU_BENCHMARK_RESIDENCE.policy.minimumResidenceDays;
const RESIDENCE_SINCE = SWIYU_BENCHMARK_RESIDENCE.residenceSince;
const NULLIFIER_DOMAIN = "swy-nf-control-v1";
const NULLIFIER_PROFILE_VERSION = "swiyu.age-over-18.scoped-nullifier.v1";
const NULLIFIER_CREDENTIAL_UID = SWIYU_BENCHMARK_NULLIFIER_CREDENTIAL_UID_HEX;
const NULLIFIER_HOLDER_SECRET = fromHex(SWIYU_BENCHMARK_NULLIFIER_HOLDER_SECRET_HEX);
const NULLIFIER_SECRET_COMMITMENT = sha256(concatBytes(domainBytes("swy-nf-sec-v1"), NULLIFIER_HOLDER_SECRET));
const NULLIFIER_SCOPE = Object.freeze({
  registryNamespaceId: hashNullifierIdentifier(SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.registryNamespace, "registry namespace"),
  verifierOriginHash: hashNullifierIdentifier(SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.verifierOrigin, "verifier origin"),
  programId: hashNullifierIdentifier(SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.program, "program"),
  claimTypeId: hashNullifierIdentifier(SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.claimType, "claim type"),
  epoch: SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.epoch,
  eligibilityPolicyDigest: hashNullifierIdentifier(SWIYU_BENCHMARK_NULLIFIER_SCOPE_IDS.eligibilityPolicy, "eligibility policy"),
});

const ITERATIONS = Number(arg("--iterations") ?? "1000");
const RUNS = Number(arg("--runs") ?? "3");
const ADAPTIVE = process.argv.includes("--adaptive");
const OUTPUT = arg("--out");
const ASSEMBLE_DIR = arg("--assemble-workers");

interface ProfileConfig {
  issuer: string;
  vct: string;
  predicate: string;
  privacyDifference: string;
  disclosures: readonly DisclosureClaim[];
  payloadExtension?: Json;
  policy: Json;
  validate(payload: Json, claims: Map<string, unknown>): void;
}

const PROFILE_CONFIGS = {
  "age-over-18": {
    issuer: ACCEPTED_PERSON_ISSUER,
    vct: ACCEPTED_PERSON_VCT,
    predicate: "selectively disclose age_over_18=true",
    privacyDifference: "The control reveals age_over_18=true; the ZK profile reveals only predicate success.",
    disclosures: [["age_over_18", true]],
    policy: { disclosedClaim: ["age_over_18", true] },
    validate(_payload, claims) {
      if (claims.get("age_over_18") !== true) throw new Error("age claim absent");
    },
  },
  "resident-canton": {
    issuer: ACCEPTED_PERSON_ISSUER,
    vct: ACCEPTED_PERSON_VCT,
    predicate: "selectively disclose resident_canton=ZH; require membership in [ZH, BE]",
    privacyDifference: "The control reveals the selected canton; the ZK profile reveals only allow-list membership.",
    disclosures: [["resident_canton", "ZH"]],
    policy: { disclosedClaim: ["resident_canton", "ZH"], allowedValues: ["ZH", "BE"] },
    validate(_payload, claims) {
      const canton = claims.get("resident_canton");
      if (typeof canton !== "string" || !["ZH", "BE"].includes(canton)) throw new Error("canton not allowed");
    },
  },
  "professional-license": {
    issuer: ACCEPTED_PROFESSIONAL_ISSUER,
    vct: PROFESSIONAL_ACCEPTED_VCT,
    predicate: `require accepted professional-license VCT, exp > ${PROFESSIONAL_REQUIRED_VALID_UNTIL}, and VALID status; disclose no licence identifier`,
    privacyDifference: "The control reveals the accepted VCT and validity interval already present in the SD-JWT envelope.",
    disclosures: [],
    policy: {
      acceptedVct: PROFESSIONAL_ACCEPTED_VCT,
      requiredValidUntil: PROFESSIONAL_REQUIRED_VALID_UNTIL,
      statusRequired: "VALID (00)",
      disclosedClaims: [],
    },
    validate(payload) {
      if (payload.vct !== PROFESSIONAL_ACCEPTED_VCT) throw new Error("license VCT not accepted");
      if (typeof payload.exp !== "number" || payload.exp <= PROFESSIONAL_REQUIRED_VALID_UNTIL) throw new Error("license validity is too short");
    },
  },
  "authoritative-residence-exact": {
    issuer: ACCEPTED_RESIDENCE_ISSUER,
    vct: ACCEPTED_RESIDENCE_VCT,
    predicate: "accepted authoritative residence credential; hidden-profile policy is approved jurisdiction plus minimum residence duration",
    privacyDifference: "Exact-policy SD-JWT control: the combined residence disclosure reveals municipality_bfs and since so the verifier can evaluate the same policy; ZK authenticates that same object but hides both fields.",
    disclosures: [
      ["residence", {
        municipality_bfs: RESIDENCE_SELECTED_MUNICIPALITY_BFS,
        since: RESIDENCE_SINCE,
      }],
    ],
    policy: residencePolicy("verifier-evaluated-exact-policy"),
    validate(_payload, claims) {
      const residence = claims.get("residence");
      if (!residence || typeof residence !== "object" || Array.isArray(residence)) {
        throw new Error("combined residence disclosure is absent");
      }
      const municipality = (residence as Json).municipality_bfs;
      const since = (residence as Json).since;
      if (typeof municipality !== "number" || !Number.isInteger(municipality) || municipality < 1 || municipality > 6999 ||
          !RESIDENCE_ALLOWED_MUNICIPALITY_BFS.includes(municipality as any)) {
        throw new Error("residence municipality not approved");
      }
      if (typeof since !== "string" || parseStrictGregorianEpochDay(since) > CURRENT_EPOCH_DAY - RESIDENCE_MINIMUM_DAYS) {
        throw new Error("minimum residence duration not met");
      }
    },
  },
  "authoritative-residence-derived": {
    issuer: ACCEPTED_RESIDENCE_ISSUER,
    vct: ACCEPTED_RESIDENCE_VCT,
    predicate: "selectively disclose issuer-derived residence_eligible=true for an exact policy version",
    privacyDifference: "Age-style secondary control: raw residence details remain hidden, but policy evaluation and freshness are delegated to the issuer rather than independently proven to the verifier.",
    disclosures: [["residence_eligible", true]],
    payloadExtension: {
      residence_policy: {
        id: RESIDENCE_POLICY_ID,
        version: RESIDENCE_POLICY_VERSION,
        evaluated_at_epoch_day: CURRENT_EPOCH_DAY,
      },
    },
    policy: residencePolicy("issuer-derived-boolean"),
    validate(payload, claims) {
      assertResidencePolicyMetadata(payload);
      if (payload.residence_policy.evaluated_at_epoch_day !== CURRENT_EPOCH_DAY) {
        throw new Error("derived residence eligibility is stale");
      }
      if (claims.get("residence_eligible") !== true) throw new Error("derived residence eligibility absent");
    },
  },
  "scoped-nullifier": {
    issuer: ACCEPTED_PERSON_ISSUER,
    vct: ACCEPTED_PERSON_VCT,
    predicate: "age_over_18=true and at most one accepted claim per issuer-authenticated credential UID and canonical verifier scope",
    privacyDifference: "Functional no-ZK control: credential_uid is disclosed and directly scoped by the verifier. The ZK profile instead proves an issuer-authenticated UID and wallet-secret commitment, derives a hidden credential seed, and reveals only its scoped nullifier.",
    disclosures: [
      ["age_over_18", true],
      ["credential_uid", NULLIFIER_CREDENTIAL_UID],
    ],
    payloadExtension: {
      nullifier_profile: NULLIFIER_PROFILE_VERSION,
      nullifier_secret_commitment: b64url(NULLIFIER_SECRET_COMMITMENT),
    },
    policy: {
      basePredicate: ["age_over_18", true],
      currentTime: NOW,
      noZkControlDomain: NULLIFIER_DOMAIN,
      zkDomains: ["swy-nf-sec-v1", "swy-nf-cred-v1", "swy-nf-scope-v1", "swy-nf-val-v1"],
      profileVersion: NULLIFIER_PROFILE_VERSION,
      scope: renderNullifierScope(),
      credentialBinding: "issuer-authenticated credential UID plus wallet-generated secret commitment; no-ZK baseline reveals UID and does not claim nullifier-byte parity",
      stateSemantics: "indexed lookup followed by proof/credential verification and atomic insert; acceptance requires insert success",
      stateBenchmarkSchema: "swiyu.nullifier-state-benchmark.v2",
    },
    validate(payload, claims) {
      if (payload.nullifier_profile !== NULLIFIER_PROFILE_VERSION) throw new Error("nullifier profile mismatch");
      if (claims.get("age_over_18") !== true) throw new Error("age claim absent");
      const credentialUid = claims.get("credential_uid");
      if (typeof credentialUid !== "string" || !/^[0-9a-f]{64}$/.test(credentialUid)) {
        throw new Error("credential UID is not a high-entropy canonical value");
      }
      if (payload.nullifier_secret_commitment !== b64url(NULLIFIER_SECRET_COMMITMENT)) throw new Error("nullifier secret commitment mismatch");
    },
  },
} satisfies Record<string, ProfileConfig>;

type ControlProfile = keyof typeof PROFILE_CONFIGS;
const PROFILE = parseProfile(arg("--profile") ?? "age-over-18");
const CONFIG: ProfileConfig = PROFILE_CONFIGS[PROFILE];

interface Fixture {
  issuerJwk: ReturnType<typeof publicJwk>;
  holderJwk: ReturnType<typeof publicJwk>;
  jwt: string;
  disclosures: string[];
  compactCredential: string;
  // Two status bits per entry, four entries per byte.
  statusList: Uint8Array;
}

interface PreparedCredential {
  fixture: Fixture;
  header: Json;
  payload: Json;
  claims: Map<string, unknown>;
  holderJwk: ReturnType<typeof publicJwk>;
}

if (ASSEMBLE_DIR) {
  if (process.argv.includes("--worker")) {
    throw new Error("--assemble-workers and --worker are mutually exclusive");
  }
  const rawRuns = readdirSync(ASSEMBLE_DIR)
    .filter((name) => /^worker-\d+\.json$/.test(name))
    .sort((left, right) => Number(left.match(/\d+/)![0]) - Number(right.match(/\d+/)![0]))
    .map((name) => JSON.parse(readFileSync(`${ASSEMBLE_DIR}/${name}`, "utf8")));
  const rendered = renderControlReport(rawRuns);
  if (OUTPUT) writeFileSync(OUTPUT, rendered);
  process.stdout.write(rendered);
} else if (!process.argv.includes("--worker")) {
  const self = fileURLToPath(import.meta.url);
  const rawRuns: Array<Record<string, any>> = [];
  const runWorkerProcess = (index: number) => {
    const workerArgv = ["--experimental-strip-types", self, "--worker", "--iterations", String(ITERATIONS), "--run", String(index + 1), "--profile", PROFILE];
    const startedAt = new Date().toISOString();
    const stdout = execFileSync(process.execPath, workerArgv, { encoding: "utf8", maxBuffer: 16 * 1024 * 1024 });
    return { ...JSON.parse(stdout), processArgv: [process.execPath, ...workerArgv], startedAt, endedAt: new Date().toISOString() };
  };
  rawRuns.push(runWorkerProcess(0), runWorkerProcess(1));
  const firstTwoVaryOver15Percent = controlVariationOver15Percent(rawRuns);
  const requiredRuns = ADAPTIVE ? (firstTwoVaryOver15Percent ? 7 : 3) : RUNS;
  while (rawRuns.length < requiredRuns) rawRuns.push(runWorkerProcess(rawRuns.length));
  const rendered = renderControlReport(rawRuns, requiredRuns);
  if (OUTPUT) writeFileSync(OUTPUT, rendered);
  process.stdout.write(rendered);
} else {
  process.stdout.write(`${JSON.stringify(runWorker(Number(arg("--run") ?? "1")))}\n`);
}

function renderControlReport(
  rawRuns: Array<Record<string, any>>,
  explicitRequiredRuns?: number,
) {
  if (rawRuns.length < 2) throw new Error("at least two fresh control workers are required");
  rawRuns.forEach((run, index) => {
    if (run.profile !== PROFILE || run.run !== index + 1 ||
        run.iterations !== ITERATIONS || run.coldIterations !== 1) {
      throw new Error(`control worker ${index + 1} has inconsistent identity or iteration counts`);
    }
  });
  const firstTwoVaryOver15Percent = controlVariationOver15Percent(rawRuns);
  const requiredRuns = explicitRequiredRuns ?? (firstTwoVaryOver15Percent ? 7 : 3);
  if (rawRuns.length !== requiredRuns) {
    throw new Error(`control requires exactly ${requiredRuns} workers, received ${rawRuns.length}`);
  }
  const report = {
    schema: "swiyu.no-zk-sd-jwt-control-benchmark.v3",
    profile: PROFILE,
    generatedAt: new Date().toISOString(),
    runtime: { node: process.version, platform: process.platform, arch: process.arch },
    semantics: {
      predicate: CONFIG.predicate,
      authoritativeLookup: { issuer: CONFIG.issuer, kid: ACCEPTED_ISSUER_KID, vct: CONFIG.vct },
      holderBinding: "ES256 kb+jwt binds nonce, audience, sd_hash, and, for scoped-nullifier, its canonical scope and nullifier",
      status: `pre-authenticated packed two-bit status bytes bound to URI ${STATUS_LIST_URI} and index ${STATUS_INDEX}; network fetch, JWT authentication, decompression, and DID resolution are outside both timed paths`,
      privacyDifference: CONFIG.privacyDifference,
    },
    policy: CONFIG.policy,
    iterationsPerRun: ITERATIONS,
    coldIterationsPerRun: 1,
    repetitionRule: {
      adaptive: true,
      thresholdRelativeToFirstTwoMean: 0.15,
      principalStages: adaptivePrincipalStages(),
      firstTwoPrincipalStageVariationOver15Percent: firstTwoVaryOver15Percent,
      requiredRuns,
      satisfied: rawRuns.length === requiredRuns,
    },
    rawRuns,
    coldSummary: summarizeRuns(rawRuns, "coldTimings"),
    summary: summarizeRuns(rawRuns),
  };
  return `${JSON.stringify(report, null, 2)}\n`;
}

function principalStages() {
  return [
    "oneTimeTrustMaterialSetup",
    "perCredentialReusableWalletPreparation",
    "perPresentationWallet",
    "perPresentationVerifierStateless",
    "perPresentationEndToEndWithUncachedCredentialValidation",
  ];
}

function controlVariationOver15Percent(runs: Array<Record<string, any>>) {
  return adaptivePrincipalStages().some((qualifiedStage) => {
    const first = controlStage(runs[0], qualifiedStage).wallMsPerOperation;
    const second = controlStage(runs[1], qualifiedStage).wallMsPerOperation;
    return Math.abs(first - second) / ((first + second) / 2) > 0.15;
  });
}

function adaptivePrincipalStages() {
  return ["cold", "steadyState"].flatMap((mode) =>
    principalStages().map((stage) => `${mode}.${stage}`));
}

function controlStage(run: Record<string, any>, qualifiedStage: string) {
  const separator = qualifiedStage.indexOf(".");
  const mode = qualifiedStage.slice(0, separator);
  const stage = qualifiedStage.slice(separator + 1);
  const bucket = mode === "cold" ? run.coldTimings : run.timings;
  const value = bucket?.[stage];
  if (!value) throw new Error(`missing control timing ${qualifiedStage}`);
  return value;
}

function runWorker(run: number) {
  const fixture = buildFixture();

  const coldSetup = measure(1, () => loadTrustMaterial(fixture));
  const coldPreparedHolder: { value?: PreparedCredential } = {};
  const coldReusable = measure(1, () => {
    coldPreparedHolder.value = prepareCredential(fixture);
  });
  const coldPrepared = coldPreparedHolder.value!;
  let coldPresentation = "";
  const coldWallet = measure(1, () => {
    coldPresentation = createPresentation(coldPrepared);
  });
  const coldVerifier = measure(1, () => {
    verifyPresentation(coldPresentation, fixture);
  });
  const coldFull = measure(1, () => {
    const locallyPrepared = prepareCredential(fixture);
    verifyPresentation(createPresentation(locallyPrepared), fixture);
  });

  for (let i = 0; i < 100; i++) {
    const prepared = prepareCredential(fixture);
    verifyPresentation(createPresentation(prepared), fixture);
  }

  const setup = measure(ITERATIONS, () => loadTrustMaterial(fixture));
  const preparedHolder: { value?: PreparedCredential } = {};
  const reusable = measure(ITERATIONS, () => { preparedHolder.value = prepareCredential(fixture); });
  const prepared = preparedHolder.value!;
  let presentation = "";
  const wallet = measure(ITERATIONS, () => { presentation = createPresentation(prepared); });
  const verifier = measure(ITERATIONS, () => { verifyPresentation(presentation, fixture); });
  const full = measure(ITERATIONS, () => {
    const locallyPrepared = prepareCredential(fixture);
    verifyPresentation(createPresentation(locallyPrepared), fixture);
  });
  const preparedStorage = encoder.encode(JSON.stringify({
    compactCredential: fixture.compactCredential,
    holderJwk: prepared.holderJwk,
    issuerJwk: fixture.issuerJwk,
    statusIndex: STATUS_INDEX,
  })).byteLength;
  const scoped = PROFILE === "scoped-nullifier" ? scopedNullifier(prepared) : undefined;
  const packedStatusIdentity = PROFILE.startsWith("authoritative-residence-")
    ? SWIYU_BENCHMARK_RESIDENCE_STATUS.packedV2
    : SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2;

  return {
    profile: PROFILE,
    run,
    iterations: ITERATIONS,
    coldIterations: 1,
    coldTimings: {
      oneTimeTrustMaterialSetup: coldSetup,
      perCredentialReusableWalletPreparation: coldReusable,
      perPresentationWallet: coldWallet,
      perPresentationVerifier: coldVerifier,
      perPresentationVerifierStateless: coldVerifier,
      perPresentationEndToEndWithUncachedCredentialValidation: coldFull,
    },
    timings: {
      oneTimeTrustMaterialSetup: setup,
      perCredentialReusableWalletPreparation: reusable,
      perPresentationWallet: wallet,
      perPresentationVerifier: verifier,
      perPresentationVerifierStateless: verifier,
      perPresentationEndToEndWithUncachedCredentialValidation: full,
    },
    sizes: {
      storedCredentialBytes: encoder.encode(fixture.compactCredential).byteLength,
      preparedCredentialStorageBytes: preparedStorage,
      transmittedPresentationBytes: encoder.encode(presentation).byteLength,
      issuerPublicJwkBytes: encoder.encode(JSON.stringify(fixture.issuerJwk)).byteLength,
      holderPublicJwkBytes: encoder.encode(JSON.stringify(fixture.holderJwk)).byteLength,
      ...(scoped ? { scopeHashBytes: scoped.scopeHash.length, nullifierBytes: scoped.nullifier.length } : {}),
    },
    correctness: correctnessChecks(prepared),
    fixtureIdentity: {
      compactCredentialSha256: b64url(sha256(encoder.encode(fixture.compactCredential))),
      issuerJwtSha256: b64url(sha256(encoder.encode(fixture.jwt))),
      disclosureSha256: fixture.disclosures.map((value) =>
        b64url(sha256(encoder.encode(value)))),
    },
    statusSnapshotIdentity: {
      uri: STATUS_LIST_URI,
      index: STATUS_INDEX,
      listLength: fixture.statusList.length * 4,
      selectedValue: packedStatusValue(fixture.statusList, STATUS_INDEX),
      epoch: PROFILE.startsWith("authoritative-residence-")
        ? SWIYU_BENCHMARK_RESIDENCE_STATUS.epoch
        : SWIYU_BENCHMARK_AGE_PACKED_STATUS_V2.epoch,
      treeProfile: packedStatusIdentity.treeProfile,
      packedChunkRoot: packedStatusIdentity.snapshotRoot,
    },
    processPeakRssBytes: process.resourceUsage().maxRSS * 1024,
  };
}

function buildFixture(): Fixture {
  const issuerJwk = publicJwk(ISSUER_SECRET, ACCEPTED_ISSUER_KID);
  const holderJwk = publicJwk(HOLDER_SECRET);
  const disclosures = CONFIG.disclosures.map(([name, value], index) =>
    b64url(encoder.encode(JSON.stringify([benchmarkDisclosureSalt(index), name, value]))),
  );
  const digests = disclosures.map((disclosure) => b64url(sha256(encoder.encode(disclosure))));
  const header = {
    alg: "ES256",
    typ: "dc+sd-jwt",
    kid: issuerJwk.kid,
    profile_version: "swiss-profile-vc:1.0.0",
  };
  const payload = {
    iss: CONFIG.issuer,
    vct: CONFIG.vct,
    iat: 1_700_000_000,
    nbf: 1_700_000_000,
    exp: 1_800_000_000,
    cnf: { jwk: holderJwk },
    status: { status_list: { uri: STATUS_LIST_URI, idx: STATUS_INDEX } },
    _sd_alg: "sha-256",
    _sd: digests,
    ...(CONFIG.payloadExtension ?? {}),
  };
  const jwt = signJwt(header, payload, ISSUER_SECRET);
  const statusList = new Uint8Array(Math.ceil(65_536 / 4));
  const compactCredential = `${jwt}~${disclosures.length ? `${disclosures.join("~")}~` : ""}`;
  return { issuerJwk, holderJwk, jwt, disclosures, compactCredential, statusList };
}

function loadTrustMaterial(fixture: Fixture) {
  const issuer = pointFromJwk(fixture.issuerJwk);
  const holder = pointFromJwk(fixture.holderJwk);
  if (issuer.length !== 65 || holder.length !== 65) throw new Error("invalid public key");
  return { issuer, holder };
}

function prepareCredential(fixture: Fixture): PreparedCredential {
  const compactParts = fixture.compactCredential.split("~");
  const jwt = compactParts.shift();
  const empty = compactParts.pop();
  const disclosures = compactParts;
  if (!jwt || empty !== "") throw new Error("invalid compact SD-JWT");
  const [encodedHeader, encodedPayload, encodedSignature] = jwt.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) throw new Error("invalid issuer JWT");
  const headerJson = decoder.decode(fromB64url(encodedHeader));
  const payloadJson = decoder.decode(fromB64url(encodedPayload));
  const header = parseCanonicalCompactJson(headerJson, "protected header") as Json;
  const payload = parseCanonicalCompactJson(payloadJson, "issuer payload") as Json;
  if (header.alg !== "ES256" || header.typ !== "dc+sd-jwt" ||
      header.kid !== ACCEPTED_ISSUER_KID ||
      header.profile_version !== "swiss-profile-vc:1.0.0") {
    throw new Error("invalid protected header");
  }
  if (payload.iss !== CONFIG.issuer || payload.vct !== CONFIG.vct) throw new Error("credential issuer or VCT does not match authoritative policy");
  if (!p256.verify(fromB64url(encodedSignature), sha256(encoder.encode(`${encodedHeader}.${encodedPayload}`)), pointFromJwk(fixture.issuerJwk))) {
    throw new Error("issuer signature mismatch");
  }
  validateTimes(payload);
  const digests = payload._sd as string[];
  const decodedClaims = disclosures.map((disclosure) => {
    if (!digests.includes(b64url(sha256(encoder.encode(disclosure))))) throw new Error("disclosure digest mismatch");
    const source = decoder.decode(fromB64url(disclosure));
    const claim = parseCanonicalCompactJson(source, "disclosure") as unknown[];
    validateDisclosureWire(source, claim);
    return claim;
  });
  const claims = new Map<string, unknown>();
  for (const claim of decodedClaims) {
    const name = String(claim[1]);
    if (claims.has(name)) throw new Error(`duplicate disclosed claim ${name}`);
    claims.set(name, claim[2]);
  }
  CONFIG.validate(payload, claims);
  const holderJwk = payload.cnf.jwk as ReturnType<typeof publicJwk>;
  pointFromJwk(holderJwk);
  return { fixture, header, payload, claims, holderJwk };
}

function createPresentation(prepared: PreparedCredential): string {
  const sdHash = b64url(sha256(encoder.encode(prepared.fixture.compactCredential)));
  const scoped = PROFILE === "scoped-nullifier" ? scopedNullifier(prepared) : undefined;
  const kbJwt = signJwt(
    { alg: "ES256", typ: "kb+jwt" },
    {
      nonce: NONCE,
      aud: AUDIENCE,
      iat: NOW,
      sd_hash: sdHash,
      ...(scoped ? {
        scope_hash: b64url(scoped.scopeHash),
        nullifier: b64url(scoped.nullifier),
      } : {}),
    },
    HOLDER_SECRET,
  );
  return `${prepared.fixture.compactCredential}${kbJwt}`;
}

function verifyPresentation(presentation: string, fixture: Fixture): true {
  const parts = presentation.split("~");
  if (parts.length < 2) throw new Error("invalid presentation");
  const jwt = parts.shift();
  const kbJwt = parts.pop();
  if (!jwt || !kbJwt) throw new Error("invalid presentation");
  const disclosures = parts;
  const compactCredential = `${jwt}~${disclosures.length ? `${disclosures.join("~")}~` : ""}`;
  const credential = prepareCredential({ ...fixture, compactCredential, disclosures });

  const status = credential.payload.status as { status_list?: { uri?: unknown; idx?: unknown } };
  if (status.status_list?.uri !== STATUS_LIST_URI || status.status_list.idx !== STATUS_INDEX) throw new Error("status reference mismatch");
  if (packedStatusValue(fixture.statusList, STATUS_INDEX) !== 0) throw new Error("credential not VALID (00)");

  const [kbHeaderB64, kbPayloadB64, kbSignatureB64] = kbJwt.split(".");
  if (!kbHeaderB64 || !kbPayloadB64 || !kbSignatureB64) throw new Error("invalid holder JWT");
  const kbHeader = JSON.parse(decoder.decode(fromB64url(kbHeaderB64))) as Json;
  const kbPayload = JSON.parse(decoder.decode(fromB64url(kbPayloadB64))) as Json;
  if (kbHeader.alg !== "ES256" || kbHeader.typ !== "kb+jwt") throw new Error("invalid holder header");
  if (!p256.verify(fromB64url(kbSignatureB64), sha256(encoder.encode(`${kbHeaderB64}.${kbPayloadB64}`)), pointFromJwk(credential.holderJwk))) {
    throw new Error("holder signature mismatch");
  }
  if (kbPayload.nonce !== NONCE || kbPayload.aud !== AUDIENCE || kbPayload.iat !== NOW) throw new Error("holder context mismatch");
  if (kbPayload.sd_hash !== b64url(sha256(encoder.encode(compactCredential)))) throw new Error("sd_hash mismatch");
  if (PROFILE === "scoped-nullifier") {
    const expected = scopedNullifier(credential);
    if (kbPayload.scope_hash !== b64url(expected.scopeHash) || kbPayload.nullifier !== b64url(expected.nullifier)) {
      throw new Error("scoped nullifier mismatch");
    }
  }
  return true;
}

function scopedNullifier(prepared: PreparedCredential) {
  const credentialUid = prepared.claims.get("credential_uid");
  if (typeof credentialUid !== "string") throw new Error("credential UID absent");
  const scopeHash = computeNullifierScopeDigest();
  // Ordinary SD-JWT cannot prove knowledge of the committed holder secret.
  // Its functional baseline therefore scopes the disclosed random credential
  // UID directly. This intentionally does not claim byte parity with the ZK
  // nullifier, but both values enter the identical spent-state transition.
  const nullifier = sha256(concatBytes(
    domainBytes(NULLIFIER_DOMAIN),
    fromHex(credentialUid),
    scopeHash,
  ));
  return { scopeHash, nullifier };
}

function correctnessChecks(prepared: PreparedCredential) {
  const base = { validPresentationAccepted: true, packedStatusValue: packedStatusValue(prepared.fixture.statusList, STATUS_INDEX) };
  if (PROFILE === "authoritative-residence-exact") {
    return {
      ...base,
      exactCombinedDisclosureGrammarRejects: {
        duplicateObjectKey: rejects(() => parseCanonicalCompactJson(
          `["AQIDBAUGBwgJCgsMDQ4PEA","residence",{"municipality_bfs":261,"municipality_bfs":351,"since":"2023-01-01"}]`,
          "disclosure",
        )),
        nonCanonicalSalt: rejects(() => validateDisclosureWire(
          `["AQIDBAUGBwgJCgsMDQ4PEB","residence",{"municipality_bfs":261,"since":"2023-01-01"}]`,
          ["AQIDBAUGBwgJCgsMDQ4PEB", "residence", { municipality_bfs: 261, since: "2023-01-01" }],
        )),
        malformedTuple: rejects(() => validateDisclosureWire(
          `["AQIDBAUGBwgJCgsMDQ4PEA","residence"]`,
          ["AQIDBAUGBwgJCgsMDQ4PEA", "residence"],
        )),
        reversedObjectKeys: rejects(() => validateDisclosureWire(
          `["AQIDBAUGBwgJCgsMDQ4PEA","residence",{"since":"2023-01-01","municipality_bfs":261}]`,
          ["AQIDBAUGBwgJCgsMDQ4PEA", "residence", { since: "2023-01-01", municipality_bfs: 261 }],
        )),
      },
    };
  }
  if (PROFILE !== "scoped-nullifier") return base;
  const first = scopedNullifier(prepared);
  const second = scopedNullifier(prepared);
  const changedScopeHash = computeNullifierScopeDigest(NULLIFIER_SCOPE.epoch + 1n);
  const changed = sha256(concatBytes(
    domainBytes(NULLIFIER_DOMAIN),
    fromHex(String(prepared.claims.get("credential_uid"))),
    changedScopeHash,
  ));
  return {
    ...base,
    deterministicWithinScope: equalBytes(first.nullifier, second.nullifier),
    differentAcrossScopes: !equalBytes(first.nullifier, changed),
    stateEnforcementMeasuredSeparately: true,
  };
}

function rejects(operation: () => void): boolean {
  try {
    operation();
    return false;
  } catch {
    return true;
  }
}

function parseCanonicalCompactJson(source: string, label: string): unknown {
  let parsed: unknown;
  try {
    parsed = JSON.parse(source);
  } catch (error) {
    throw new Error(`${label} is not valid JSON`, { cause: error });
  }
  // The benchmark VCT freezes JSON.stringify's compact spelling. This rejects
  // duplicate keys, whitespace, escapes, alternate number spellings, and key
  // orders that the corresponding fixed-position circuit does not accept.
  if (JSON.stringify(parsed) !== source) {
    throw new Error(`${label} is not in the exact canonical compact JSON grammar`);
  }
  return parsed;
}

function packedStatusValue(bytes: Uint8Array, index: number) {
  const byte = bytes[Math.floor(index / 4)];
  return (byte >>> ((index % 4) * 2)) & 0b11;
}

function residencePolicy(controlKind: string) {
  return {
    controlKind,
    policyId: RESIDENCE_POLICY_ID,
    policyVersion: RESIDENCE_POLICY_VERSION,
    municipalityDirectoryAsOf: RESIDENCE_DIRECTORY_AS_OF,
    municipalityDirectorySha256: SWIYU_BENCHMARK_RESIDENCE.policy.municipalityDirectorySha256,
    allowedMunicipalityBfsCodes: [...RESIDENCE_ALLOWED_MUNICIPALITY_BFS],
    maximumAllowedMunicipalities: 16,
    minimumResidenceDays: RESIDENCE_MINIMUM_DAYS,
    currentEpochDay: CURRENT_EPOCH_DAY,
    statusRequired: "VALID (00)",
  };
}

function benchmarkDisclosureSalt(index: number): string {
  if (PROFILE === "authoritative-residence-exact" && index === 0) {
    return SWIYU_BENCHMARK_RESIDENCE.disclosureSalt;
  }
  return b64url(sha256(encoder.encode(`swiyu-benchmark-disclosure-salt-${index}`)).slice(0, 16));
}

function validateDisclosureWire(source: string, claim: unknown[]): void {
  if (!Array.isArray(claim) || claim.length !== 3 || typeof claim[0] !== "string" ||
      typeof claim[1] !== "string") {
    throw new Error("disclosure must be an exact [salt,name,value] tuple");
  }
  const saltBytes = fromB64url(claim[0]);
  if (saltBytes.length !== 16) {
    throw new Error("benchmark disclosure salt must be canonical unpadded base64url for 16 bytes");
  }
  if (PROFILE === "authoritative-residence-exact") {
    const residence = claim[2];
    if (claim[1] !== "residence" || !residence || typeof residence !== "object" ||
        Array.isArray(residence) || Object.keys(residence).join(",") !== "municipality_bfs,since" ||
        source !== JSON.stringify(claim)) {
      throw new Error("residence disclosure does not match the exact combined VCT grammar");
    }
  }
}

function parseStrictGregorianEpochDay(value: string) {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
  if (!match) throw new Error("residence_since must use strict YYYY-MM-DD");
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (year < 1900 || year > 2199) throw new Error("residence_since year must be within 1900..2199");
  const milliseconds = Date.UTC(year, month - 1, day);
  const date = new Date(milliseconds);
  if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) {
    throw new Error("residence_since is not a valid Gregorian date");
  }
  return Math.floor(milliseconds / 86_400_000);
}

function computeNullifierScopeDigest(epoch = NULLIFIER_SCOPE.epoch) {
  return sha256(concatBytes(
    domainBytes("swy-nf-scope-v1"),
    NULLIFIER_SCOPE.registryNamespaceId,
    NULLIFIER_SCOPE.verifierOriginHash,
    NULLIFIER_SCOPE.programId,
    NULLIFIER_SCOPE.claimTypeId,
    u64be(epoch),
    NULLIFIER_SCOPE.eligibilityPolicyDigest,
  ));
}

function hashNullifierIdentifier(value: string, label: string) {
  const bytes = encoder.encode(value);
  if (bytes.length === 0 || bytes.length > 1_024) throw new Error(`${label} has invalid UTF-8 length`);
  return sha256(concatBytes(domainBytes("swy-nf-id-v1"), u16be(bytes.length), bytes));
}

function renderNullifierScope() {
  return {
    registryNamespaceId: b64url(NULLIFIER_SCOPE.registryNamespaceId),
    verifierOriginHash: b64url(NULLIFIER_SCOPE.verifierOriginHash),
    programId: b64url(NULLIFIER_SCOPE.programId),
    claimTypeId: b64url(NULLIFIER_SCOPE.claimTypeId),
    epoch: NULLIFIER_SCOPE.epoch.toString(),
    eligibilityPolicyDigest: b64url(NULLIFIER_SCOPE.eligibilityPolicyDigest),
    digest: b64url(computeNullifierScopeDigest()),
  };
}

function domainBytes(value: string) {
  const bytes = encoder.encode(value);
  return concatBytes(u16be(bytes.length), bytes);
}

function u16be(value: number) { return Uint8Array.of(value >>> 8, value & 0xff); }
function u64be(value: bigint) {
  const bytes = new Uint8Array(8);
  let remaining = value;
  for (let index = 7; index >= 0; index--) { bytes[index] = Number(remaining & 0xffn); remaining >>= 8n; }
  return bytes;
}
function concatBytes(...parts: Uint8Array[]) {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) { result.set(part, offset); offset += part.length; }
  return result;
}
function fromHex(value: string) { return new Uint8Array(Buffer.from(value, "hex")); }

function assertResidencePolicyMetadata(payload: Json) {
  if (payload.residence_policy?.id !== RESIDENCE_POLICY_ID || payload.residence_policy?.version !== RESIDENCE_POLICY_VERSION) {
    throw new Error("residence policy metadata mismatch");
  }
}

function validateTimes(payload: Json) {
  if (typeof payload.nbf !== "number" || typeof payload.exp !== "number") throw new Error("missing validity interval");
  if (NOW < payload.nbf || NOW >= payload.exp) throw new Error("credential outside validity interval");
}

function signJwt(header: Json, payload: Json, secret: Uint8Array): string {
  const h = b64url(encoder.encode(JSON.stringify(header)));
  const p = b64url(encoder.encode(JSON.stringify(payload)));
  const input = `${h}.${p}`;
  const signature = p256.sign(sha256(encoder.encode(input)), secret).toCompactRawBytes();
  return `${input}.${b64url(signature)}`;
}

function publicJwk(secret: Uint8Array, kid?: string) {
  const point = p256.ProjectivePoint.fromPrivateKey(secret).toAffine();
  return { kty: "EC" as const, crv: "P-256" as const, x: b64url(numberBytes(point.x)), y: b64url(numberBytes(point.y)), ...(kid ? { kid } : {}) };
}

function pointFromJwk(jwk: { x: string; y: string }) {
  return Uint8Array.from([4, ...fromB64url(jwk.x), ...fromB64url(jwk.y)]);
}

function measure(iterations: number, operation: () => unknown) {
  const cpuBefore = process.cpuUsage();
  const wallBefore = process.hrtime.bigint();
  for (let i = 0; i < iterations; i++) operation();
  const wallNs = Number(process.hrtime.bigint() - wallBefore);
  const cpu = process.cpuUsage(cpuBefore);
  return {
    wallMsPerOperation: wallNs / 1e6 / iterations,
    cpuMsPerOperation: (cpu.user + cpu.system) / 1000 / iterations,
    totalWallMs: wallNs / 1e6,
    totalCpuMs: (cpu.user + cpu.system) / 1000,
  };
}

function summarizeRuns(
  runs: Array<Record<string, any>>,
  bucket: "coldTimings" | "timings" = "timings",
) {
  const summary = Object.fromEntries(principalStages().map((stage) => {
    const wall = runs.map((run) => run[bucket][stage].wallMsPerOperation);
    const cpu = runs.map((run) => run[bucket][stage].cpuMsPerOperation);
    return [stage, { wallMs: stats(wall), cpuMs: stats(cpu) }];
  }));
  // Compatibility alias for the existing aggregate. Stateful nullifier cost is
  // never hidden here; it is composed from the separate common-state report.
  summary.perPresentationVerifier = summary.perPresentationVerifierStateless;
  return summary;
}

function stats(values: number[]) {
  const sorted = [...values].sort((a, b) => a - b);
  const mean = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.length > 1 ? values.reduce((sum, value) => sum + (value - mean) ** 2, 0) / (values.length - 1) : 0;
  const standardDeviation = Math.sqrt(variance);
  const deviations = values.map((value) => Math.abs(value - sorted[Math.floor(sorted.length / 2)])).sort((a, b) => a - b);
  return {
    min: sorted[0], median: sorted[Math.floor(sorted.length / 2)], max: sorted.at(-1), mean,
    variance, standardDeviation, coefficientOfVariation: mean === 0 ? 0 : standardDeviation / mean,
    medianAbsoluteDeviation: deviations[Math.floor(deviations.length / 2)],
    raw: values,
  };
}

function equalBytes(a: Uint8Array, b: Uint8Array) {
  return a.length === b.length && a.every((value, index) => value === b[index]);
}
function b64url(bytes: Uint8Array) { return Buffer.from(bytes).toString("base64url"); }
function fromB64url(value: string) {
  if (!/^[A-Za-z0-9_-]*$/.test(value) || value.includes("=")) {
    throw new Error("non-canonical base64url value");
  }
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (b64url(decoded) !== value) throw new Error("non-canonical base64url value");
  return decoded;
}
function numberBytes(value: bigint) { return Uint8Array.from(Buffer.from(value.toString(16).padStart(64, "0"), "hex")); }
function scalar(value: bigint) { return numberBytes(value); }
function arg(name: string) { const index = process.argv.indexOf(name); return index === -1 ? undefined : process.argv[index + 1]; }
function parseProfile(value: string): ControlProfile {
  if (value in PROFILE_CONFIGS) return value as ControlProfile;
  throw new Error(`unsupported profile: ${value}; expected one of ${Object.keys(PROFILE_CONFIGS).join(", ")}`);
}
