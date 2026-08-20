import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { WitnessTester } from "circomkit";
import { sha256Pad } from "@zk-email/helpers";
import { p256 } from "@noble/curves/nist.js";

import { circomkit } from "../common/index.ts";

const padAscii = (text: string, length: number): bigint[] => {
  const bytes = [...Buffer.from(text, "utf8")].map(BigInt);
  assert(bytes.length <= length);
  return [...bytes, ...Array<bigint>(length - bytes.length).fill(0n)];
};

const bigintTo32 = (value: bigint): Buffer =>
  Buffer.from(value.toString(16).padStart(64, "0"), "hex");

const malleateBase64urlTail = (encoded: string): string => {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(encoded.at(-1)!);
  assert(last >= 0);
  const replacement = alphabet[last + 1];
  assert(replacement !== undefined);
  return `${encoded.slice(0, -1)}${replacement}`;
};

describe("swiyu fixed-profile components", function () {
  this.timeout(900_000);

  describe("strict ISO date", () => {
    let circuit: WitnessTester<["bytes"], ["numeric"]>;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuIsoDate", {
        file: "swiyu/date",
        template: "IsoDate1900To2199",
        params: [],
        recompile: true,
      });
    });

    it("accepts a real leap day and normalizes it", async () => {
      const witness = await circuit.calculateWitness({
        bytes: [...Buffer.from("2000-02-29")],
      });
      await circuit.expectConstraintPass(witness);
      const { numeric } = await circuit.readWitnessSignals(witness, ["numeric"]);
      assert.equal(numeric, 20_000_229n);
    });

    for (const invalid of ["1900-02-29", "2100-02-29", "2001-04-31", "2001-00-10", "2001-13-10"]) {
      it(`rejects invalid date ${invalid}`, async () => {
        await assert.rejects(circuit.calculateWitness({ bytes: [...Buffer.from(invalid)] }));
      });
    }
  });

  describe("quote-aware JSON field selection", () => {
    let circuit: WitnessTester<
      ["json", "jsonLength", "keyBytes", "keyStart", "value", "valueLength"],
      ["ok"]
    >;
    const maxLen = 128;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuJsonString", {
        file: "swiyu/test-harnesses",
        template: "JsonTopStringHarness",
        params: [maxLen, 3, 32],
        recompile: true,
      });
    });

    const inputFor = (json: string, keyStart = json.indexOf('"iss":')) => ({
      json: padAscii(json, maxLen),
      jsonLength: BigInt(Buffer.byteLength(json)),
      keyBytes: [...Buffer.from("iss")],
      keyStart: BigInt(keyStart),
      value: padAscii("did:example:issuer", 32),
      valueLength: 18n,
    });

    it("accepts a canonical compact member", async () => {
      const json = '{"note":"ordinary","iss":"did:example:issuer"}';
      const witness = await circuit.calculateWitness(inputFor(json));
      await circuit.expectConstraintPass(witness);
    });

    it("rejects escaped key-shaped aliases instead of decoding them differently", async () => {
      const json = '{"note":"\\\"iss\\\":\\\"evil\\\"","iss":"did:example:issuer"}';
      await assert.rejects(circuit.calculateWitness(inputFor(json, json.lastIndexOf('"iss":'))));
    });

    it("rejects a duplicate security key", async () => {
      const json = '{"iss":"did:example:issuer","iss":"did:example:issuer"}';
      await assert.rejects(circuit.calculateWitness(inputFor(json)));
    });

    it("rejects a host offset at the wrong object depth", async () => {
      const json = '{"nested":{"iss":"did:example:issuer"},"iss":"did:example:issuer"}';
      await assert.rejects(circuit.calculateWitness(inputFor(json, json.indexOf('"iss":'))));
    });

    for (const malformed of [
      '{"note":"x" "iss":"did:example:issuer"}',
      '{"note","x","iss":"did:example:issuer"}',
      '{"note":"x",,"iss":"did:example:issuer"}',
      '{"note":"x","iss":"did:example:issuer",}',
      '{"note":[},"iss":"did:example:issuer"}',
    ]) {
      it(`rejects malformed compact JSON ${malformed}`, async () => {
        await assert.rejects(circuit.calculateWitness(inputFor(malformed)));
      });
    }

    it("rejects whitespace outside strings", async () => {
      const json = '{"note":"x", "iss":"did:example:issuer"}';
      await assert.rejects(circuit.calculateWitness(inputFor(json)));
    });
  });

  describe("clear-claim exclusion", () => {
    let circuit: WitnessTester<["json", "jsonLength", "keyBytes"], ["ok"]>;
    const maxLen = 128;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuForbiddenBirthdate", {
        file: "swiyu/test-harnesses",
        template: "JsonForbiddenTopKeyHarness",
        params: [maxLen, 9],
        recompile: true,
      });
    });

    const input = (json: string) => ({
      json: padAscii(json, maxLen),
      jsonLength: BigInt(json.length),
      keyBytes: [...Buffer.from("birthdate")],
    });

    it("rejects an exact top-level clear birthdate", async () => {
      await assert.rejects(circuit.calculateWitness(input('{"birthdate":"2012-01-01"}')));
    });

    it("rejects an escaped spelling that a host parser could alias to birthdate", async () => {
      await assert.rejects(circuit.calculateWitness(input('{"birthd\\u0061te":"2012-01-01"}')));
    });

    it("allows an unrelated canonical claim", async () => {
      const witness = await circuit.calculateWitness(input('{"given_name":"Alice"}'));
      await circuit.expectConstraintPass(witness);
    });
  });

  describe("required swiyu header profile version", () => {
    let circuit: WitnessTester<["json", "jsonLength", "keyStart"], ["ok"]>;
    const maxLen = 128;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuHeaderProfileVersion", {
        file: "swiyu/test-harnesses",
        template: "HeaderProfileVersionHarness",
        params: [maxLen],
        recompile: true,
      });
    });

    const input = (json: string, keyStart = json.indexOf('"profile_version":')) => ({
      json: padAscii(json, maxLen),
      jsonLength: BigInt(json.length),
      keyStart: BigInt(keyStart),
    });

    it("accepts exactly swiss-profile-vc:1.0.0", async () => {
      const json = '{"alg":"ES256","profile_version":"swiss-profile-vc:1.0.0"}';
      const witness = await circuit.calculateWitness(input(json));
      await circuit.expectConstraintPass(witness);
    });

    it("rejects a missing or wrong profile version and duplicate key", async () => {
      await assert.rejects(circuit.calculateWitness(input('{"alg":"ES256"}', 0)));
      await assert.rejects(circuit.calculateWitness(input('{"profile_version":"swiss-profile-vc:1.0.1"}')));
      const duplicate = '{"profile_version":"swiss-profile-vc:1.0.0","profile_version":"swiss-profile-vc:1.0.0"}';
      await assert.rejects(circuit.calculateWitness(input(duplicate)));
    });
  });

  describe("unsigned compact-JSON integers", () => {
    let circuit: WitnessTester<
      ["json", "jsonLength", "keyBytes", "keyStart", "digitLength"],
      ["value"]
    >;
    const maxLen = 64;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuJsonUint", {
        file: "swiyu/test-harnesses",
        template: "JsonTopUintHarness",
        params: [maxLen, 3, 10],
        recompile: true,
      });
    });

    for (const value of [0, 1, 42, 131_071, 99_999_999, 999_999_999, 1_700_000_000]) {
      it(`accumulates ${value} without multiplying through disabled slots`, async () => {
        const raw = String(value);
        const json = `{"nbf":${raw}}`;
        const witness = await circuit.calculateWitness({
          json: padAscii(json, maxLen),
          jsonLength: BigInt(json.length),
          keyBytes: [...Buffer.from("nbf")],
          keyStart: 1n,
          digitLength: BigInt(raw.length),
        });
        await circuit.expectConstraintPass(witness);
        const result = await circuit.readWitnessSignals(witness, ["value"]);
        assert.equal(result.value, BigInt(value));
      });
    }
  });

  describe("compact-JWS separator bounds", () => {
    let circuit: WitnessTester<
      ["message", "messageLength", "periodIndex"],
      ["headerFirst", "payloadFirst"]
    >;
    const maxMessageLength = 1_600;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuHeaderPayloadBoundaries", {
        file: "swiyu/header-extractor-test-harness",
        template: "HeaderPayloadExtractorHarness",
        params: [maxMessageLength, 4, 1_536],
        recompile: true,
      });
    });

    const paddedSigningInput = (realLength: number) => {
      const header = Buffer.from("{}").toString("base64url");
      const payloadB64Length = realLength - header.length - 1;
      const decodedLength = Math.floor((payloadB64Length * 3) / 4);
      const payload = JSON.stringify({ x: "a".repeat(decodedLength - 8) });
      const encodedPayload = Buffer.from(payload).toString("base64url");
      assert.equal(encodedPayload.length, payloadB64Length);
      const signingInput = Buffer.from(`${header}.${encodedPayload}`);
      const [padded, paddedLength] = sha256Pad(signingInput, maxMessageLength);
      return {
        message: [...padded],
        messageLength: BigInt(paddedLength),
        periodIndex: BigInt(header.length),
      };
    };

    for (const realLength of [1_471, 1_472, 1_503, 1_504]) {
      it(`counts the period only inside a ${realLength}-byte signed prefix`, async () => {
        const witness = await circuit.calculateWitness(paddedSigningInput(realLength));
        await circuit.expectConstraintPass(witness);
        const result = await circuit.readWitnessSignals(witness, ["headerFirst", "payloadFirst"]);
        assert.equal(result.headerFirst, 123n);
        assert.equal(result.payloadFirst, 123n);
      });
    }
  });

  describe("birthdate disclosure", () => {
    let circuit: WitnessTester<
      ["encodedPadded", "encodedLength", "decodedLength", "saltLength"],
      ["birthdateNumeric", "digestBytes"]
    >;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuBirthdateDisclosure", {
        file: "swiyu/disclosure",
        template: "SwiyuBirthdateDisclosure",
        params: [],
        recompile: true,
      });
    });

    const encode = (name = "birthdate", value = "2000-02-29", salt = "abcdefghijklmnopqrstuvwx") => {
      const decoded = Buffer.from(JSON.stringify([salt, name, value]), "utf8");
      const encoded = Buffer.from(decoded).toString("base64url");
      const [padded] = sha256Pad(Buffer.from(encoded, "utf8"), 128);
      return {
        input: {
          encodedPadded: [...padded],
          encodedLength: BigInt(encoded.length),
          decodedLength: BigInt(decoded.length),
          saltLength: BigInt(salt.length),
        },
        encoded,
      };
    };

    it("binds the exact tuple, date and SHA-256 digest", async () => {
      const { input, encoded } = encode();
      const witness = await circuit.calculateWitness(input);
      await circuit.expectConstraintPass(witness);
      const signals = await circuit.readWitnessSignals(witness, ["birthdateNumeric", "digestBytes"]);
      assert.equal(signals.birthdateNumeric, 20_000_229n);
      const expected = [...createHash("sha256").update(encoded, "utf8").digest()].map(BigInt);
      assert.deepEqual(signals.digestBytes, expected);
    });

    it("rejects an alias claim name and a fourth tuple element", async () => {
      await assert.rejects(circuit.calculateWitness(encode("date_of_birth").input));
      const salt = "abcdefghijklmnopqrstuvwx";
      const decoded = Buffer.from(JSON.stringify([salt, "birthdate", "2000-02-29", "extra"]));
      const encoded = decoded.toString("base64url");
      const [padded] = sha256Pad(Buffer.from(encoded), 128);
      await assert.rejects(circuit.calculateWitness({
        encodedPadded: [...padded],
        encodedLength: BigInt(encoded.length),
        decodedLength: BigInt(decoded.length),
        saltLength: BigInt(salt.length),
      }));
    });

    it("rejects noncanonical SHA padding", async () => {
      const { input } = encode();
      const tampered = [...input.encodedPadded];
      tampered[tampered.length - 1] ^= 1;
      await assert.rejects(circuit.calculateWitness({ ...input, encodedPadded: tampered }));
    });

    it("rejects a disclosure spelling with non-zero unused base64url bits", async () => {
      const { input, encoded } = encode();
      const malleated = malleateBase64urlTail(encoded);
      assert.deepEqual(Buffer.from(malleated, "base64url"), Buffer.from(encoded, "base64url"));
      const [padded] = sha256Pad(Buffer.from(malleated), 128);
      await assert.rejects(circuit.calculateWitness({ ...input, encodedPadded: [...padded] }));
    });
  });

  describe("canonical 32-byte base64url values", () => {
    let circuit: WitnessTester<["encoded"], ["ok"]>;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuCanonicalBase64Url32", {
        file: "swiyu/test-harnesses",
        template: "CanonicalBase64Url32Harness",
        params: [],
        recompile: true,
      });
    });

    it("accepts the unique digest spelling and rejects an equivalent residual-bit alias", async () => {
      const encoded = createHash("sha256").update("canonical-vector").digest("base64url");
      assert.equal(encoded.length, 43);
      const witness = await circuit.calculateWitness({ encoded: [...Buffer.from(encoded)] });
      await circuit.expectConstraintPass(witness);

      const malleated = malleateBase64urlTail(encoded);
      assert.deepEqual(Buffer.from(malleated, "base64url"), Buffer.from(encoded, "base64url"));
      await assert.rejects(circuit.calculateWitness({ encoded: [...Buffer.from(malleated)] }));
    });
  });

  describe("P-256 public-key validity", () => {
    let pointCircuit: WitnessTester<["x", "y"], ["ok"]>;
    let encodedCircuit: WitnessTester<["xEncoded", "yEncoded"], ["x", "y"]>;
    const generator = p256.ProjectivePoint.BASE.toAffine();
    const xEncoded = bigintTo32(generator.x).toString("base64url");
    const yEncoded = bigintTo32(generator.y).toString("base64url");

    before(async () => {
      pointCircuit = await circomkit.WitnessTester("SwiyuP256Point", {
        file: "swiyu/test-harnesses",
        template: "P256PointHarness",
        params: [],
        recompile: true,
      });
      encodedCircuit = await circomkit.WitnessTester("SwiyuP256EncodedPoint", {
        file: "swiyu/test-harnesses",
        template: "P256EncodedPointHarness",
        params: [],
        recompile: true,
      });
    });

    it("accepts a finite on-curve point and its canonical JWK coordinates", async () => {
      const pointWitness = await pointCircuit.calculateWitness(generator);
      await pointCircuit.expectConstraintPass(pointWitness);
      const encodedWitness = await encodedCircuit.calculateWitness({
        xEncoded: [...Buffer.from(xEncoded)],
        yEncoded: [...Buffer.from(yEncoded)],
      });
      await encodedCircuit.expectConstraintPass(encodedWitness);
      const decoded = await encodedCircuit.readWitnessSignals(encodedWitness, ["x", "y"]);
      assert.equal(decoded.x, generator.x);
      assert.equal(decoded.y, generator.y);
    });

    it("rejects infinity, an off-curve point, and a coordinate outside the base field", async () => {
      await assert.rejects(pointCircuit.calculateWitness({ x: 0n, y: 0n }));
      await assert.rejects(pointCircuit.calculateWitness({ x: generator.x, y: generator.y + 1n }));

      const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
      await assert.rejects(encodedCircuit.calculateWitness({
        xEncoded: [...Buffer.from(bigintTo32(p).toString("base64url"))],
        yEncoded: [...Buffer.from(yEncoded)],
      }));
    });

    it("rejects a coordinate alias with non-zero unused base64url bits", async () => {
      const malleatedX = malleateBase64urlTail(xEncoded);
      assert.deepEqual(Buffer.from(malleatedX, "base64url"), Buffer.from(xEncoded, "base64url"));
      await assert.rejects(encodedCircuit.calculateWitness({
        xEncoded: [...Buffer.from(malleatedX)],
        yEncoded: [...Buffer.from(yEncoded)],
      }));
    });
  });

  describe("v1 metadata commitment", () => {
    let circuit: WitnessTester<
      ["challengeHash", "iss", "issLength", "kid", "kidLength", "vct", "vctLength"],
      ["hashHi", "hashLo"]
    >;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuMetadataV1", {
        file: "swiyu/metadata",
        template: "SwiyuMetadataCommitment",
        params: [112],
        recompile: true,
      });
    });

    it("matches the independent 448-byte record vector", async () => {
      const challengeHash = 0x123456789abcdef00112233445566778899aabbccddeeffn;
      const iss = "did:example:issuer";
      const kid = "did:example:issuer#key-1";
      const vct = "https://example.ch/vct/person";
      const record = Buffer.alloc(448);
      record.set(Buffer.from("swiyu-age18-status-v1\0"), 0);
      record.set(bigintTo32(challengeHash), 22);
      record[54] = Buffer.byteLength(iss); record.set(Buffer.from(iss), 55);
      record[167] = Buffer.byteLength(kid); record.set(Buffer.from(kid), 168);
      record[280] = Buffer.byteLength(vct); record.set(Buffer.from(vct), 281);
      const expected = createHash("sha256").update(record).digest();

      const witness = await circuit.calculateWitness({
        challengeHash,
        iss: padAscii(iss, 112), issLength: BigInt(iss.length),
        kid: padAscii(kid, 112), kidLength: BigInt(kid.length),
        vct: padAscii(vct, 112), vctLength: BigInt(vct.length),
      });
      await circuit.expectConstraintPass(witness);
      const result = await circuit.readWitnessSignals(witness, ["hashHi", "hashLo"]);
      assert.equal(result.hashHi, BigInt(`0x${expected.subarray(0, 16).toString("hex")}`));
      assert.equal(result.hashLo, BigInt(`0x${expected.subarray(16).toString("hex")}`));
    });

    it("rejects the scalar-order boundary that could otherwise alias a bit decomposition", async () => {
      const q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
      const common = {
        iss: padAscii("i", 112), issLength: 1n,
        kid: padAscii("k", 112), kidLength: 1n,
        vct: padAscii("v", 112), vctLength: 1n,
      };
      const witness = await circuit.calculateWitness({ challengeHash: q - 1n, ...common });
      await circuit.expectConstraintPass(witness);
      await assert.rejects(circuit.calculateWitness({ challengeHash: q, ...common }));
    });
  });

  describe("fixed-index status Merkle proof", () => {
    let circuit: WitnessTester<
      ["statusIndex", "statusValue", "siblings", "listLength", "epoch"],
      ["treeRoot", "snapshotRoot"]
    >;
    const depth = 4;

    const hashDomain = (domain: string, ...parts: Uint8Array[]): Uint8Array => {
      const name = Buffer.from(domain, "utf8");
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(name.length);
      return createHash("sha256").update(Buffer.concat([prefix, name, ...parts])).digest();
    };
    const u32 = (value: number): Uint8Array => {
      const bytes = Buffer.alloc(4);
      bytes.writeUInt32BE(value);
      return bytes;
    };
    const u64 = (value: bigint): Uint8Array => {
      const bytes = Buffer.alloc(8);
      bytes.writeBigUInt64BE(value);
      return bytes;
    };

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuStatusMerkle", {
        file: "swiyu/status-merkle",
        template: "SwiyuStatusMerkle",
        params: [depth],
        recompile: true,
      });
    });

    const vector = (index: number, status = 0n) => {
      const siblings = [
        createHash("sha256").update("sibling-0").digest(),
        createHash("sha256").update("sibling-1").digest(),
        createHash("sha256").update("sibling-2").digest(),
        createHash("sha256").update("sibling-3").digest(),
      ];
      let current = hashDomain("swiyu-status-leaf-v1", u32(index), Uint8Array.of(Number(status)));
      for (let level = 0; level < depth; level++) {
        const bit = (index >> level) & 1;
        const left = bit === 0 ? current : siblings[level]!;
        const right = bit === 0 ? siblings[level]! : current;
        current = hashDomain("swiyu-status-node-v1", left, right);
      }
      const snapshot = hashDomain("swiyu-status-snapshot-v1", u32(16), u64(7n), current);
      return {
        siblings: siblings.map((digest) => [...digest]),
        treeRoot: [...current].map(BigInt),
        snapshotRoot: [...snapshot].map(BigInt),
      };
    };

    it("accepts a VALID entry with correct left/right ordering", async () => {
      const { siblings, treeRoot, snapshotRoot } = vector(5);
      const witness = await circuit.calculateWitness({
        statusIndex: 5n,
        statusValue: 0n,
        siblings,
        listLength: 16n,
        epoch: 7n,
      });
      await circuit.expectConstraintPass(witness);
      const signals = await circuit.readWitnessSignals(witness, ["treeRoot", "snapshotRoot"]);
      assert.deepEqual(signals.treeRoot, treeRoot);
      assert.deepEqual(signals.snapshotRoot, snapshotRoot);
    });

    it("rejects revoked status and an out-of-list index; a changed path changes the bound root", async () => {
      const { siblings, snapshotRoot } = vector(5);
      await assert.rejects(circuit.calculateWitness({ statusIndex: 5n, statusValue: 1n, siblings, listLength: 16n, epoch: 7n }));
      await assert.rejects(circuit.calculateWitness({ statusIndex: 5n, statusValue: 2n, siblings, listLength: 16n, epoch: 7n }));
      await assert.rejects(circuit.calculateWitness({ statusIndex: 5n, statusValue: 0n, siblings, listLength: 5n, epoch: 7n }));

      const changed = siblings.map((sibling) => [...sibling]);
      changed[0]![0] ^= 1;
      const changedWitness = await circuit.calculateWitness({ statusIndex: 5n, statusValue: 0n, siblings: changed, listLength: 16n, epoch: 7n });
      const changedSignals = await circuit.readWitnessSignals(changedWitness, ["snapshotRoot"]);
      assert.notDeepEqual(changedSignals.snapshotRoot, snapshotRoot);
    });
  });

  describe("fixed-index ternary status Merkle proof", () => {
    let circuit: WitnessTester<
      ["statusIndex", "statusValue", "siblings", "listLength", "epoch"],
      ["treeRoot", "snapshotRoot"]
    >;
    const depth = 3;

    const hashDomain = (domain: string, ...parts: Uint8Array[]): Uint8Array => {
      const name = Buffer.from(domain, "utf8");
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(name.length);
      return createHash("sha256").update(Buffer.concat([prefix, name, ...parts])).digest();
    };
    const u32 = (value: number): Uint8Array => {
      const bytes = Buffer.alloc(4);
      bytes.writeUInt32BE(value);
      return bytes;
    };
    const u64 = (value: bigint): Uint8Array => {
      const bytes = Buffer.alloc(8);
      bytes.writeBigUInt64BE(value);
      return bytes;
    };

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuTernaryStatusMerkle", {
        file: "swiyu/status-merkle-ternary",
        template: "SwiyuTernaryStatusMerkle",
        params: [depth],
        recompile: true,
      });
    });

    const vector = (index: number, status = 0n) => {
      const siblings = Array.from({ length: depth }, (_, level) => [
        createHash("sha256").update(`ternary-${level}-a`).digest(),
        createHash("sha256").update(`ternary-${level}-b`).digest(),
      ]);
      let current = hashDomain("swiyu-status-leaf-v1", u32(index), Uint8Array.of(Number(status)));
      let position = index;
      for (let level = 0; level < depth; level++) {
        const trit = position % 3;
        const pair = siblings[level]!;
        const children = trit === 0
          ? [current, pair[0]!, pair[1]!]
          : trit === 1
            ? [pair[0]!, current, pair[1]!]
            : [pair[0]!, pair[1]!, current];
        current = hashDomain("swiyu-status-node3-v1", ...children);
        position = Math.floor(position / 3);
      }
      const snapshot = hashDomain("swiyu-status-snapshot-v1", u32(27), u64(7n), current);
      return {
        siblings: siblings.map((pair) => pair.map((digest) => [...digest])),
        treeRoot: [...current].map(BigInt),
        snapshotRoot: [...snapshot].map(BigInt),
      };
    };

    it("authenticates all three child positions with constrained base-3 path digits", async () => {
      for (const index of [3, 4, 5]) {
        const { siblings, treeRoot, snapshotRoot } = vector(index);
        const witness = await circuit.calculateWitness({
          statusIndex: BigInt(index),
          statusValue: 0n,
          siblings,
          listLength: 27n,
          epoch: 7n,
        });
        await circuit.expectConstraintPass(witness);
        const signals = await circuit.readWitnessSignals(witness, ["treeRoot", "snapshotRoot"]);
        assert.deepEqual(signals.treeRoot, treeRoot);
        assert.deepEqual(signals.snapshotRoot, snapshotRoot);
      }
    });

    it("rejects a revoked leaf, an out-of-list index, and excess capacity", async () => {
      const { siblings } = vector(5);
      await assert.rejects(circuit.calculateWitness({ statusIndex: 5n, statusValue: 1n, siblings, listLength: 27n, epoch: 7n }));
      await assert.rejects(circuit.calculateWitness({ statusIndex: 5n, statusValue: 0n, siblings, listLength: 5n, epoch: 7n }));
      await assert.rejects(circuit.calculateWitness({ statusIndex: 5n, statusValue: 0n, siblings, listLength: 28n, epoch: 7n }));
    });
  });

  describe("packed status chunk Merkle proof v2", () => {
    let circuit: WitnessTester<
      ["statusIndex", "statusValue", "packedChunk", "siblings", "listLength", "epoch"],
      ["treeRoot", "snapshotRoot"]
    >;
    const depth = 6;

    const hashDomain = (domain: string, ...parts: Uint8Array[]): Uint8Array => {
      const name = Buffer.from(domain, "utf8");
      const prefix = Buffer.alloc(2);
      prefix.writeUInt16BE(name.length);
      return createHash("sha256").update(Buffer.concat([prefix, name, ...parts])).digest();
    };
    const u32 = (value: number): Uint8Array => {
      const bytes = Buffer.alloc(4);
      bytes.writeUInt32BE(value);
      return bytes;
    };
    const u64 = (value: bigint): Uint8Array => {
      const bytes = Buffer.alloc(8);
      bytes.writeBigUInt64BE(value);
      return bytes;
    };

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuPackedStatusChunkMerkleV2", {
        file: "swiyu/status-merkle-packed-chunk",
        template: "SwiyuPackedStatusChunkMerkleV2",
        params: [],
        recompile: true,
      });
    });

    const vector = (packedChunk: Uint8Array, index: number, listLength = 260) => {
      const chunkIndex = Math.floor(index / 256);
      const siblings = Array.from({ length: depth }, (_, level) => [
        createHash("sha256").update(`packed-${level}-a`).digest(),
        createHash("sha256").update(`packed-${level}-b`).digest(),
      ]);
      let current = hashDomain(
        "swiyu-status-chunk-v2",
        u32(chunkIndex),
        packedChunk,
      );
      let position = chunkIndex;
      for (const pair of siblings) {
        const trit = position % 3;
        const children = trit === 0
          ? [current, pair[0]!, pair[1]!]
          : trit === 1
            ? [pair[0]!, current, pair[1]!]
            : [pair[0]!, pair[1]!, current];
        current = hashDomain("swiyu-status-node3-v2", ...children);
        position = Math.floor(position / 3);
      }
      const snapshot = hashDomain(
        "swiyu-status-snapshot-v2",
        u32(listLength),
        u64(7n),
        current,
      );
      return {
        siblings: siblings.map((pair) => pair.map((digest) => [...digest])),
        treeRoot: [...current].map(BigInt),
        snapshotRoot: [...snapshot].map(BigInt),
      };
    };

    it("matches exact LSB-first index mapping across a chunk boundary", async () => {
      const chunk = new Uint8Array(64);
      chunk[0] = 0xe4;
      const { siblings, treeRoot, snapshotRoot } = vector(chunk, 256);
      const witness = await circuit.calculateWitness({
        statusIndex: 256n,
        statusValue: 0n,
        packedChunk: [...chunk],
        siblings,
        listLength: 260n,
        epoch: 7n,
      });
      await circuit.expectConstraintPass(witness);
      const signals = await circuit.readWitnessSignals(witness, ["treeRoot", "snapshotRoot"]);
      assert.deepEqual(signals.treeRoot, treeRoot);
      assert.deepEqual(signals.snapshotRoot, snapshotRoot);
      await assert.rejects(circuit.calculateWitness({
        statusIndex: 257n,
        statusValue: 0n,
        packedChunk: [...chunk],
        siblings,
        listLength: 260n,
        epoch: 7n,
      }));
    });

    it("rejects non-byte data, noncanonical tail bytes, invalid lengths, and out-of-list indices", async () => {
      const chunk = new Uint8Array(64);
      const { siblings } = vector(chunk, 256);
      const base = {
        statusIndex: 256n,
        statusValue: 0n,
        packedChunk: [...chunk],
        siblings,
        listLength: 260n,
        epoch: 7n,
      };
      const nonByte = [...chunk]; nonByte[0] = 256;
      const nonzeroTail = [...chunk]; nonzeroTail[63] = 1;
      await assert.rejects(circuit.calculateWitness({ ...base, packedChunk: nonByte }));
      await assert.rejects(circuit.calculateWitness({ ...base, packedChunk: nonzeroTail }));
      await assert.rejects(circuit.calculateWitness({ ...base, listLength: 261n }));
      await assert.rejects(circuit.calculateWitness({ ...base, statusIndex: 260n }));
      await assert.rejects(circuit.calculateWitness({ ...base, listLength: 131076n }));
    });
  });

  describe("opaque status profile commitment", () => {
    let circuit: WitnessTester<["uri", "uriLength", "snapshotRoot"], ["hashHi", "hashLo"]>;

    before(async () => {
      circuit = await circomkit.WitnessTester("SwiyuStatusProfileCommitment", {
        file: "swiyu/status-merkle",
        template: "SwiyuStatusProfileCommitment",
        params: [160],
        recompile: true,
      });
    });

    it("matches an independent fixed-record SHA-256 vector", async () => {
      const uri = "https://status.example/list/alpha";
      const snapshotRoot = createHash("sha256").update("snapshot-root-vector").digest();
      const record = Buffer.alloc(256);
      record.writeUInt16BE(23, 0);
      record.set(Buffer.from("swiyu-status-profile-v0"), 2);
      record[25] = Buffer.byteLength(uri);
      record.set(Buffer.from(uri), 26);
      record.set(snapshotRoot, 186);
      const expected = createHash("sha256").update(record).digest();
      const expectedHi = BigInt(`0x${expected.subarray(0, 16).toString("hex")}`);
      const expectedLo = BigInt(`0x${expected.subarray(16).toString("hex")}`);

      const witness = await circuit.calculateWitness({
        uri: padAscii(uri, 160),
        uriLength: BigInt(Buffer.byteLength(uri)),
        snapshotRoot: [...snapshotRoot],
      });
      await circuit.expectConstraintPass(witness);
      const signals = await circuit.readWitnessSignals(witness, ["hashHi", "hashLo"]);
      assert.equal(signals.hashHi, expectedHi);
      assert.equal(signals.hashLo, expectedLo);
    });
  });
});
