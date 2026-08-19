import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  NativeNodeSwiyuProofBackend,
  type SwiyuNativeCommandRequest,
  type SwiyuNativeCommandResult,
  type SwiyuNativeCommandRunner,
} from "../../src/swiyu-zkp/native-backend-node.js";

const PROVING_KEY_NAME = "swiyu_age18_status_2k_proving.key";
const VERIFYING_KEY_NAME = "swiyu_age18_status_2k_verifying.key";
const PROOF_NAME = "swiyu_age18_status_2k.proof";
const CONTEXT_NAME = "swiyu_age18_status_2k.public-context";
const WITNESS_NAME = "swiyu_age18_status_2k.wtns";
const VERIFY_OUTPUT =
  "verified profile=swiyu-age18-status-2k-v0 circuit=swiyu_age18_status_2k\n";

class CallbackRunner implements SwiyuNativeCommandRunner {
  readonly calls: SwiyuNativeCommandRequest[] = [];

  constructor(
    private readonly callback: (
      request: Readonly<SwiyuNativeCommandRequest>,
    ) => Promise<SwiyuNativeCommandResult>,
  ) {}

  async run(
    request: Readonly<SwiyuNativeCommandRequest>,
  ): Promise<SwiyuNativeCommandResult> {
    this.calls.push({ ...request, args: [...request.args] });
    return this.callback(request);
  }
}

describe("Node native swiyu fixed-profile backend", () => {
  it("symlinks the proving key, runs the exact CLI command, and parses ten values", async () => {
    const fixture = await makeFixture();
    let workspace = "";
    try {
      const context = makeContext(7);
      const proof = new Uint8Array([3, 1, 4, 1, 5]);
      const runner = new CallbackRunner(async (request) => {
        expect(request.executable).toBe(fixture.binary);
        expect(request.cwd).toBe(fixture.cwd);
        expect(request.args[0]).toBe("prove");
        workspace = request.args[2]!;
        expect(request.args).toEqual([
          "prove",
          join(workspace, WITNESS_NAME),
          workspace,
        ]);
        expect((await stat(workspace)).mode & 0o777).toBe(0o700);
        expect((await lstat(join(workspace, PROVING_KEY_NAME))).isSymbolicLink()).toBe(
          true,
        );
        expect(await readFile(join(workspace, WITNESS_NAME))).toEqual(
          Buffer.from([0x77, 0x74, 0x6e, 0x73]),
        );
        await writeFile(join(workspace, PROOF_NAME), proof);
        await writeFile(join(workspace, CONTEXT_NAME), context);
        return completed(`proof_bytes=${proof.length} context_bytes=320\n`);
      });
      const backend = makeBackend(fixture, runner);

      const result = await backend.proveFromWitness(
        { kind: "local-file", path: fixture.provingKey },
        new Uint8Array([0x77, 0x74, 0x6e, 0x73]),
      );

      expect(result.proof).toEqual(proof);
      expect(result.publicValues).toHaveLength(10);
      expect(result.publicValues[0]).toEqual(context.slice(0, 32));
      expect(result.publicValues[9]).toEqual(context.slice(9 * 32, 10 * 32));
      await expectMissing(workspace);
    } finally {
      await fixture.cleanup();
    }
  });

  it("writes the fixed verification artifacts and returns the expected context", async () => {
    const fixture = await makeFixture();
    let workspace = "";
    try {
      const proof = new Uint8Array([9, 8, 7]);
      const context = makeContext(11);
      const runner = new CallbackRunner(async (request) => {
        workspace = request.args[1]!;
        expect(request.args).toEqual(["verify", workspace]);
        expect((await lstat(join(workspace, VERIFYING_KEY_NAME))).isSymbolicLink()).toBe(
          true,
        );
        expect(await readFile(join(workspace, PROOF_NAME))).toEqual(Buffer.from(proof));
        expect(await readFile(join(workspace, CONTEXT_NAME))).toEqual(
          Buffer.from(context),
        );
        return completed(VERIFY_OUTPUT);
      });
      const backend = makeBackend(fixture, runner);

      const result = await backend.verify(
        proof,
        { kind: "local-file", path: fixture.verifyingKey },
        context,
      );

      expect(result.valid).toBe(true);
      expect(result.publicValues).toHaveLength(10);
      expect(result.publicValues.flatMap((value) => [...value])).toEqual([...context]);
      await expectMissing(workspace);
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects byte-backed native keys and non-normalized traversal paths", async () => {
    const fixture = await makeFixture();
    try {
      const runner = new CallbackRunner(async () => {
        throw new Error("runner must not be called");
      });
      const backend = makeBackend(fixture, runner);
      await expect(
        backend.proveFromWitness(new Uint8Array([1]), new Uint8Array([2])),
      ).rejects.toThrow(/local-file/);
      await expect(
        backend.verify(
          new Uint8Array([1]),
          new Uint8Array([2]),
          makeContext(),
        ),
      ).rejects.toThrow(/local-file/);

      const traversal = `${fixture.cwd}/../proving.key`;
      await expect(
        backend.proveFromWitness(
          { kind: "local-file", path: traversal },
          new Uint8Array([2]),
        ),
      ).rejects.toThrow(/absolute normalized local path/);
      expect(runner.calls).toHaveLength(0);
    } finally {
      await fixture.cleanup();
    }
  });

  it("fails closed on nonzero verification exit and malformed success output", async () => {
    const fixture = await makeFixture();
    const workspaces: string[] = [];
    try {
      const results = [
        completed("", "invalid proof", 1),
        completed("not-the-cli-contract\n"),
      ];
      const runner = new CallbackRunner(async (request) => {
        workspaces.push(request.args[1]!);
        return results.shift()!;
      });
      const backend = makeBackend(fixture, runner);
      const key = { kind: "local-file" as const, path: fixture.verifyingKey };

      const badExit = await backend.verify(
        new Uint8Array([1]),
        key,
        makeContext(),
      );
      const malformed = await backend.verify(
        new Uint8Array([1]),
        key,
        makeContext(),
      );

      expect(badExit).toMatchObject({ valid: false, publicValues: [] });
      expect(badExit.error).toMatch(/exit 1.*invalid proof/);
      expect(malformed).toEqual({
        valid: false,
        publicValues: [],
        error: "swiyu native verify returned malformed success output",
      });
      await Promise.all(workspaces.map(expectMissing));
    } finally {
      await fixture.cleanup();
    }
  });

  it("rejects malformed prover context and always removes a failed workspace", async () => {
    const fixture = await makeFixture();
    const workspaces: string[] = [];
    try {
      const runner = new CallbackRunner(async (request) => {
        const workspace = request.args[2]!;
        workspaces.push(workspace);
        if (workspaces.length === 1) {
          await writeFile(join(workspace, PROOF_NAME), new Uint8Array([1]));
          await writeFile(join(workspace, CONTEXT_NAME), new Uint8Array(319));
          return completed("proof_bytes=1 context_bytes=319\n");
        }
        throw new Error("injected command failure");
      });
      const backend = makeBackend(fixture, runner);
      const key = { kind: "local-file" as const, path: fixture.provingKey };

      await expect(
        backend.proveFromWitness(key, new Uint8Array([1])),
      ).rejects.toThrow(/public context must contain exactly 320 bytes/);
      await expect(
        backend.proveFromWitness(key, new Uint8Array([2])),
      ).rejects.toThrow(/injected command failure/);
      await Promise.all(workspaces.map(expectMissing));
    } finally {
      await fixture.cleanup();
    }
  });

  it("enforces timeout and combined command-output bounds without a shell", async () => {
    const fixture = await makeFixture();
    try {
      const proveScript = join(fixture.cwd, "prove");
      await writeFile(proveScript, "setInterval(() => {}, 1_000);\n", {
        mode: 0o600,
      });
      const timeoutBackend = new NativeNodeSwiyuProofBackend({
        binaryPath: process.execPath,
        cwd: fixture.cwd,
        tempRoot: fixture.root,
        proveTimeoutMs: 50,
        maxCommandOutputBytes: 128,
      });
      const key = { kind: "local-file" as const, path: fixture.provingKey };
      await expect(
        timeoutBackend.proveFromWitness(key, new Uint8Array([1])),
      ).rejects.toThrow(/timed out/);

      await writeFile(
        proveScript,
        'process.stdout.write("x".repeat(4_096)); setInterval(() => {}, 1_000);\n',
      );
      const boundedBackend = new NativeNodeSwiyuProofBackend({
        binaryPath: process.execPath,
        cwd: fixture.cwd,
        tempRoot: fixture.root,
        proveTimeoutMs: 5_000,
        maxCommandOutputBytes: 64,
      });
      await expect(
        boundedBackend.proveFromWitness(key, new Uint8Array([1])),
      ).rejects.toThrow(/output limit/);

      expect((await readdir(fixture.root)).filter((name) => name.startsWith("swiyu-native-"))).toEqual(
        [],
      );
    } finally {
      await fixture.cleanup();
    }
  });

  it("uses independent workspaces for concurrent proofs", async () => {
    const fixture = await makeFixture();
    const workspaces: string[] = [];
    let release!: () => void;
    const bothStarted = new Promise<void>((resolve) => {
      release = resolve;
    });
    try {
      const runner = new CallbackRunner(async (request) => {
        const workspace = request.args[2]!;
        workspaces.push(workspace);
        if (workspaces.length === 2) release();
        await bothStarted;
        const witness = await readFile(request.args[1]!);
        const marker = witness[0]!;
        const proof = new Uint8Array([marker]);
        await writeFile(join(workspace, PROOF_NAME), proof);
        await writeFile(join(workspace, CONTEXT_NAME), makeContext(marker));
        return completed("proof_bytes=1 context_bytes=320\n");
      });
      const backend = makeBackend(fixture, runner);
      const key = { kind: "local-file" as const, path: fixture.provingKey };

      const [first, second] = await Promise.all([
        backend.proveFromWitness(key, new Uint8Array([1])),
        backend.proveFromWitness(key, new Uint8Array([2])),
      ]);

      expect(first.proof).toEqual(new Uint8Array([1]));
      expect(second.proof).toEqual(new Uint8Array([2]));
      expect(new Set(workspaces).size).toBe(2);
      await Promise.all(workspaces.map(expectMissing));
    } finally {
      await fixture.cleanup();
    }
  });
});

function completed(
  stdout: string,
  stderr = "",
  exitCode = 0,
): SwiyuNativeCommandResult {
  return {
    exitCode,
    signal: null,
    stdout,
    stderr,
    termination: "completed",
  };
}

function makeContext(seed = 0): Uint8Array {
  const context = new Uint8Array(320);
  for (let scalar = 0; scalar < 10; scalar++) {
    context[scalar * 32] = (seed + scalar) & 0xff;
  }
  return context;
}

async function makeFixture() {
  const root = await mkdtemp(join(tmpdir(), "swiyu-native-test-"));
  const cwd = join(root, "cwd");
  const provingKey = join(root, "proving.key");
  const verifyingKey = join(root, "verifying.key");
  const binary = join(root, "swiyu-profile");
  await mkdir(cwd);
  await Promise.all([
    writeFile(provingKey, new Uint8Array([1, 2, 3])),
    writeFile(verifyingKey, new Uint8Array([4, 5, 6])),
  ]);
  return {
    root,
    cwd,
    provingKey,
    verifyingKey,
    binary,
    async cleanup() {
      await rm(root, { recursive: true, force: true });
    },
  };
}

function makeBackend(
  fixture: Awaited<ReturnType<typeof makeFixture>>,
  commandRunner: SwiyuNativeCommandRunner,
) {
  return new NativeNodeSwiyuProofBackend({
    binaryPath: fixture.binary,
    cwd: fixture.cwd,
    tempRoot: fixture.root,
    proveTimeoutMs: 5_000,
    verifyTimeoutMs: 5_000,
    maxCommandOutputBytes: 4_096,
    commandRunner,
  });
}

async function expectMissing(path: string): Promise<void> {
  await expect(access(path)).rejects.toMatchObject({ code: "ENOENT" });
}
