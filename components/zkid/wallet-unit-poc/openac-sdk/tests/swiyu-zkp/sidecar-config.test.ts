import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { afterEach, describe, expect, it } from "vitest";
import { SwiyuVerifierSidecarService } from "../../src/index.js";
import {
  loadSwiyuSidecarFromConfigFile,
  provisionSwiyuAuthoritativeStatusSnapshotFromFile,
} from "../../src/swiyu-zkp/sidecar-node.js";
import type { SwiyuAuthoritativeStatusSnapshot } from "../../src/swiyu-zkp/types.js";
import { base64urlEncode } from "../../src/utils.js";
import {
  CHECKED_IN_DID_TDW_KID,
  ISSUER_PRIVATE_KEY,
  publicJwk,
  signJwt,
} from "./fixture.js";

const ISSUER = "did:example:issuer";
const SUBJECT = "https://status.example.ch/lists/2026-07";
const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((path) => rm(path, {
    recursive: true,
    force: true,
  })));
});

describe("local signed status-list sidecar provisioning", () => {
  it("derives the verifier snapshot from the bounded local JWT at startup", async () => {
    const fixture = await writeConfigFixture();
    const expected = await provisionSwiyuAuthoritativeStatusSnapshotFromFile({
      jwtPath: fixture.jwtPath,
      issuerPublicKey: publicJwk(
        ISSUER_PRIVATE_KEY,
        CHECKED_IN_DID_TDW_KID,
      ),
      expectedIssuer: ISSUER,
      expectedSubject: SUBJECT,
      currentTime: BigInt(fixture.now),
    });
    const options = await loadSwiyuSidecarFromConfigFile(fixture.configPath);
    const statusRegistry = (
      options.service as unknown as {
        statusSnapshots: ReadonlyMap<string, SwiyuAuthoritativeStatusSnapshot>;
      }
    ).statusSnapshots;

    expect(options.service).toBeInstanceOf(SwiyuVerifierSidecarService);
    expect([...statusRegistry.values()]).toEqual([expected]);
    expect(expected).toMatchObject({
      id: expect.stringMatching(/^statuslist-jwt:[A-Za-z0-9_-]{43}$/),
      issuer: ISSUER,
      kid: CHECKED_IN_DID_TDW_KID,
      subject: SUBJECT,
      epoch: fixture.now - 10,
      listLength: 8,
      validBefore: BigInt(fixture.now + 590),
      provenance: expect.stringMatching(
        /^statuslist\+jwt#sha256:[A-Za-z0-9_-]{43}$/,
      ),
    });
    expect(expected).not.toHaveProperty("root");
    expect(expected).not.toHaveProperty("uri");
  });

  it.each([
    ["tampered", /signature/],
    ["stale", /stale/],
    ["wrong-key", /signature/],
  ] as const)("rejects a %s signed status-list input", async (mode, error) => {
    const fixture = await writeConfigFixture({ mode });
    await expect(
      loadSwiyuSidecarFromConfigFile(fixture.configPath),
    ).rejects.toThrow(error);
  });

  it("rejects a status-list entry with a missing subject", async () => {
    const fixture = await writeConfigFixture({ omitSubject: true });
    await expect(
      loadSwiyuSidecarFromConfigFile(fixture.configPath),
    ).rejects.toThrow(/subject is required/);
  });

  it("rejects an ambiguous issuer and kid registry", async () => {
    const fixture = await writeConfigFixture({ duplicateIssuer: true });
    await expect(
      loadSwiyuSidecarFromConfigFile(fixture.configPath),
    ).rejects.toThrow(/ambiguously repeats an issuer and kid/);
  });

  it("rejects duplicate snapshot IDs derived from local JWT bytes", async () => {
    const fixture = await writeConfigFixture({ duplicateStatusList: true });
    await expect(
      loadSwiyuSidecarFromConfigFile(fixture.configPath),
    ).rejects.toThrow(/duplicate snapshot id/);
  });

  it("rejects a listener timeout shorter than the native verifier timeout", async () => {
    const fixture = await writeConfigFixture({ shortListenTimeout: true });
    await expect(
      loadSwiyuSidecarFromConfigFile(fixture.configPath),
    ).rejects.toThrow(/verification_timeout_ms must be at least/);
  });
});

interface ConfigFixtureOptions {
  mode?: "valid" | "tampered" | "stale" | "wrong-key";
  omitSubject?: boolean;
  duplicateIssuer?: boolean;
  duplicateStatusList?: boolean;
  shortListenTimeout?: boolean;
}

async function writeConfigFixture(
  options: ConfigFixtureOptions = {},
): Promise<{ root: string; configPath: string; jwtPath: string; now: number }> {
  const root = await mkdtemp(join(tmpdir(), "swiyu-sidecar-config-"));
  roots.push(root);
  const now = Math.floor(Date.now() / 1_000);
  const jwtPath = join(root, "status-list.jwt");
  const verifyingKeyPath = join(root, "verifying.key");
  let compactJwt = makeStatusListJwt(now, options.mode === "stale");
  if (options.mode === "tampered") {
    const parts = compactJwt.split(".") as [string, string, string];
    const first = parts[2][0] === "A" ? "B" : "A";
    compactJwt = `${parts[0]}.${parts[1]}.${first}${parts[2].slice(1)}`;
  }
  await Promise.all([
    writeFile(jwtPath, compactJwt, { mode: 0o600 }),
    writeFile(verifyingKeyPath, new Uint8Array([1]), { mode: 0o600 }),
  ]);

  const wrongKey = new Uint8Array(32);
  wrongKey[31] = 7;
  const publicKey = publicJwk(
    options.mode === "wrong-key" ? wrongKey : ISSUER_PRIVATE_KEY,
    CHECKED_IN_DID_TDW_KID,
  );
  const issuer = {
    issuer: ISSUER,
    kid: CHECKED_IN_DID_TDW_KID,
    public_key: publicKey,
    vct_values: ["https://example.ch/vct/person"],
    trust_anchors: [],
  };
  const statusList: Record<string, string> = {
    jwt_file: "./status-list.jwt",
    issuer: ISSUER,
    kid: CHECKED_IN_DID_TDW_KID,
    subject: SUBJECT,
  };
  if (options.omitSubject) delete statusList.subject;
  const listen: Record<string, string | number> = {
    host: "127.0.0.1",
    port: 7788,
    path: "/v1/verify",
  };
  const nativeBackend: Record<string, string | number> = {
    binary: "./swiyu-profile",
    cwd: ".",
  };
  if (options.shortListenTimeout) {
    listen.verification_timeout_ms = 100;
    nativeBackend.verify_timeout_ms = 200;
  }
  const configuration = {
    listen,
    native_backend: nativeBackend,
    verifying_key: "./verifying.key",
    issuers: options.duplicateIssuer ? [issuer, issuer] : [issuer],
    status_lists: options.duplicateStatusList
      ? [statusList, statusList]
      : [statusList],
  };
  const configPath = join(root, "sidecar.json");
  await writeFile(configPath, JSON.stringify(configuration), { mode: 0o600 });
  return { root, configPath, jwtPath, now };
}

function makeStatusListJwt(now: number, stale: boolean): string {
  const iat = stale ? now - 1_000 : now - 10;
  const exp = stale ? now - 1 : now + 600;
  const header = {
    alg: "ES256",
    kid: CHECKED_IN_DID_TDW_KID,
    typ: "statuslist+jwt",
    profile_version: "swiss-profile-vc:1.0.0",
  };
  const payload = {
    iss: ISSUER,
    sub: SUBJECT,
    iat,
    exp,
    ttl: 600,
    status_list: {
      bits: 2,
      lst: base64urlEncode(
        new Uint8Array(deflateSync(new Uint8Array([0xe4, 0x1b]))),
      ),
    },
  };
  return signJwt(JSON.stringify(header), JSON.stringify(payload));
}
