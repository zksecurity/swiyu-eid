import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readlinkSync } from "node:fs";

const root = process.argv[2] ?? process.cwd();
const git = (...args) => execFileSync("git", ["-C", root, ...args]);
const commit = git("rev-parse", "HEAD").toString().trim();
const status = git("status", "--porcelain=v1", "-z");
const diff = git("diff", "--binary", "HEAD", "--", "wallet-unit-poc");
const files = git(
  "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "wallet-unit-poc",
).toString().split("\0").filter(Boolean).sort();
const tree = createHash("sha256");
for (const path of files) {
  tree.update(Buffer.from(path));
  tree.update(Buffer.from([0]));
  const absolute = `${root}/${path}`;
  tree.update(lstatSync(absolute).isSymbolicLink()
    ? Buffer.from(`symlink:${readlinkSync(absolute)}`)
    : readFileSync(absolute));
  tree.update(Buffer.from([0]));
}
process.stdout.write(`${JSON.stringify({
  commit,
  dirty: status.length > 0,
  statusSha256: sha(status),
  diffSha256: sha(diff),
  sourceTreeSha256: tree.digest("hex"),
  fileCount: files.length,
}, null, 2)}\n`);

function sha(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}
