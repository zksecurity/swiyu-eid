import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync } from "node:fs";

const root = process.argv[2];
if (!root) throw new Error("usage: external-source-fingerprint.mjs GIT_ROOT");
const git = (...args) => execFileSync("git", ["-C", root, ...args]);
const status = git("status", "--porcelain=v1", "-z");
const files = git("ls-files", "-z", "--cached").toString().split("\0").filter(Boolean).sort();
const tree = createHash("sha256");
for (const path of files) {
  tree.update(path).update("\0");
  const absolute = `${root}/${path}`;
  tree.update(lstatSync(absolute).isSymbolicLink()
    ? Buffer.from(`symlink:${readlinkSync(absolute)}`)
    : readFileSync(absolute));
  tree.update("\0");
}
process.stdout.write(`${JSON.stringify({
  commit: git("rev-parse", "HEAD").toString().trim(),
  gitTree: git("rev-parse", "HEAD^{tree}").toString().trim(),
  dirty: status.length > 0,
  statusSha256: createHash("sha256").update(status).digest("hex"),
  sourceTreeSha256: tree.digest("hex"),
  trackedFileCount: files.length,
}, null, 2)}\n`);
