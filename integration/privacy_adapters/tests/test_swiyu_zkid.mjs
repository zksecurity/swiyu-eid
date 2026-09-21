import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { collect } from "../swiyu-zkid.mjs";

const ROOT = dirname(fileURLToPath(import.meta.url));
const COLLECTOR = join(ROOT, "..", "swiyu-zkid.mjs");
const HARNESS = join(ROOT, "../../harness");
const FORBIDDEN_KINDS = new Set([
  "missing_compare_path",
  "context_mismatch",
  "unexpected_public_difference",
]);

function caseById(bundle, id) {
  return bundle.cases.find((item) => item.id === id);
}

function requireCase(bundle, id) {
  const found = caseById(bundle, id);
  assert.ok(found, `missing case ${id}`);
  return found;
}

function getPointer(doc, pointer) {
  if (pointer === "") return doc;
  assert.equal(pointer.startsWith("/"), true, `invalid pointer ${pointer}`);
  let cur = doc;
  for (const raw of pointer.slice(1).split("/")) {
    const token = raw.replaceAll("~1", "/").replaceAll("~0", "~");
    assert.ok(cur != null && Object.hasOwn(cur, token), `${pointer} missing on view`);
    cur = cur[token];
  }
  return cur;
}

describe("swiyu-zkid privacy adapter collect()", async () => {
  const bundle = await collect();

  it("emits a generic analyzer bundle with the integration provider id", () => {
    assert.equal(bundle.schema, "swiyu.privacy-traces.v1");
    assert.equal(bundle.provider.id, "swiyu-zkid-integration");
    assert.equal(typeof bundle.provider.title, "string");
    assert.ok(Array.isArray(bundle.cases));
    assert.ok(bundle.cases.length >= 8);
  });

  it("labels wrappers as integration except the test-only AND/OR control", () => {
    for (const item of bundle.cases) {
      assert.match(item.evidence_kind, /^(integration|crypto|control)$/);
      if (item.id === "ctrl-hidden-branch-and-or-clean") {
        assert.equal(item.evidence_kind, "control");
        continue;
      }
      assert.notEqual(item.evidence_kind, "control");
      if (!item.skip_reason) {
        assert.ok(item.records.length > 0, item.id);
        for (const record of item.records) {
          assert.ok(record.view && typeof record.view === "object", record.id);
          assert.notEqual(Object.keys(record.view).length, 0, record.id);
          assert.ok(record.subject);
          assert.ok(record.session);
          assert.ok(record.scope);
          assert.equal(typeof record.expected_outcome, "string");
          assert.equal(typeof record.outcome, "string");
        }
      }
    }
  });

  it("resolves every declared JSON pointer on the matching record views", () => {
    for (const item of bundle.cases) {
      if (item.skip_reason) continue;
      for (const record of item.records) {
        for (const pointer of [...item.opaque_paths, ...item.compare_paths]) {
          getPointer(record.view, pointer);
        }
        for (const pointer of Object.keys(record.allowed_public || {})) {
          getPointer(record.view, pointer);
        }
      }
    }
  });

  it("records sidecar HTTP bodies that do not echo a planted holder secret", () => {
    const item = requireCase(bundle, "sidecar-http-secret-in-malformed-body");
    assert.equal(item.family, "failure_fallback");
    assert.equal(item.relation, "secret_scan");
    assert.equal(item.runtime, "node-sidecar-http");
    const secret = item.secrets[0].value;
    assert.match(secret, /^SYNTH-/);
    for (const record of item.records) {
      const serialized = JSON.stringify(record.view);
      assert.equal(serialized.includes(secret), false, record.id);
      assert.equal(record.view.body, '{"verified":false}');
      assert.equal(typeof record.view.http_status, "number");
    }
  });

  it("compares equal rejection bodies only under the same public method/path/type/length", () => {
    const item = requireCase(bundle, "sidecar-http-same-public-rejection");
    assert.equal(item.relation, "equivalent");
    const contexts = item.records.map((record) => JSON.stringify(record.public_context));
    assert.equal(new Set(contexts).size, 1);
    const bodies = new Set(item.records.map((record) => record.view.body));
    assert.deepEqual([...bodies], ['{"verified":false}']);
    assert.equal(new Set(item.records.map((record) => record.view.http_status)).size, 1);
  });

  it("documents public HTTP rejection metadata without treating path/type/length as secret oracles", () => {
    const item = requireCase(bundle, "sidecar-http-rejection-metadata");
    assert.equal(item.relation, "secret_scan");
    const byId = Object.fromEntries(item.records.map((record) => [record.id, record]));
    assert.equal(byId["malformed-json"].allowed_public["/http_status"], 400);
    assert.equal(byId.oversized.allowed_public["/http_status"], 413);
    assert.equal(byId["wrong-path"].allowed_public["/http_status"], 404);
    assert.equal(byId["wrong-type"].allowed_public["/http_status"], 415);
    assert.notEqual(
      byId["malformed-json"].public_context.content_length,
      byId.oversized.public_context.content_length,
    );
    assert.notEqual(byId["wrong-path"].public_context.path, byId["malformed-json"].public_context.path);
  });

  it("wraps library sidecar verifyJson failures into a non-diagnostic rejection without collector ids in view", () => {
    const item = requireCase(bundle, "sidecar-library-rejection-equivalence");
    assert.equal(item.observer, "http-library-boundary");
    assert.equal(item.relation, "equivalent");
    for (const record of item.records) {
      assert.equal(Object.hasOwn(record.view, "id"), false);
      assert.equal(record.view.error_name, "SwiyuSidecarRejection");
      assert.equal(record.view.error_message, "presentation rejected");
    }
  });

  it("isolates mock split handles, separates cross-wallet reject, and records cancel/retry outcomes", () => {
    const isolation = requireCase(bundle, "split-prepare-handle-isolation");
    assert.equal(isolation.records.length, 2);
    assert.match(isolation.records[0].public_context.crypto_backend, /mock-split-backend/);
    assert.notEqual(
      isolation.records[0].view.prepare_handle_id,
      isolation.records[1].view.prepare_handle_id,
    );

    const cross = requireCase(bundle, "split-cross-wallet-reject");
    assert.equal(cross.relation, "secret_scan");
    assert.equal(cross.records[0].outcome, "reject");
    assert.match(cross.records[0].view.error_message, /not created by this split wallet/);

    const concurrent = requireCase(bundle, "split-prepare-concurrent");
    assert.notEqual(
      concurrent.records[0].view.prepare_proof,
      concurrent.records[1].view.prepare_proof,
    );

    const cancel = requireCase(bundle, "sidecar-http-cancel-retry");
    assert.equal(cancel.relation, "secret_scan");
    const aborted = cancel.records.find((record) => record.id === "aborted");
    const retried = cancel.records.find((record) => record.id === "retried");
    assert.equal(aborted.outcome, "abort");
    assert.equal(retried.outcome, "accept");
    assert.equal(retried.view.verified, true);
  });

  it("keeps nullifiers scoped by origin/program/epoch and recomputes nonce invariance through the scope API", () => {
    const scoped = requireCase(bundle, "nullifier-scoped-origin-program-epoch");
    assert.equal(scoped.relation, "scoped");
    const sameA = scoped.records.find((record) => record.id === "alice-origin-a-repeat");
    const sameB = scoped.records.find((record) => record.id === "alice-origin-a");
    const otherOrigin = scoped.records.find((record) => record.id === "alice-origin-b");
    assert.equal(sameA.view.nullifier, sameB.view.nullifier);
    assert.notEqual(sameA.view.nullifier, otherOrigin.view.nullifier);

    const nonce = requireCase(bundle, "nullifier-nonce-invariance");
    assert.equal(nonce.records[0].view.nullifier, nonce.records[1].view.nullifier);
    assert.notEqual(nonce.records[0].public_context.nonce, nonce.records[1].public_context.nonce);
    assert.equal(nonce.records[0].public_context.scope_api_includes_nonce, false);
  });

  it("observes only authoritativeSnapshot at the SDK projection boundary", () => {
    const item = requireCase(bundle, "status-list-authoritative-subject-uri");
    assert.equal(item.observer, "authoritative SDK projection consumer");
    assert.equal(item.relation, "secret_scan");
    assert.equal(item.records.length, 1);
    const auth = item.records[0];
    assert.equal(auth.view.has_uri_field, false);
    assert.equal(auth.view.has_root_field, false);
    assert.equal(auth.view.subject, item.secrets.find((entry) => entry.label === "status_uri").value);
    assert.equal(auth.public_context.privateSnapshot_observed, false);
    assert.match(auth.view.local_contract, /LOCAL SDK export/);
    assert.match(auth.view.local_contract, /Not a captured verifier HTTP leak/);
  });

  it("records packaging as a functional accept/reject mismatch, not a privacy comparison", () => {
    const item = requireCase(bundle, "sidecar-dist-entry-instanceof");
    assert.equal(item.relation, "secret_scan");
    assert.equal(item.records[0].expected_outcome, "accept");
    assert.equal(item.records[0].outcome, "reject");
    assert.match(item.records[0].view.error_message, /SwiyuVerifierSidecarService is required/);
  });

  it("includes interleaved HTTP metrics and a test-only AND/OR control", () => {
    const metrics = requireCase(bundle, "sidecar-http-repeat-metrics");
    assert.equal(metrics.relation, "metrics");
    assert.equal(metrics.records.length, 16);
    const subjects = metrics.records.map((record) => record.subject);
    assert.equal(subjects.filter((s) => s === "alice").length, 8);
    assert.equal(subjects.filter((s) => s === "bob").length, 8);
    assert.notEqual(subjects.join(""), "alice".repeat(8) + "bob".repeat(8));
    for (const record of metrics.records) {
      assert.equal(record.outcome, "reject");
      assert.equal(typeof record.metrics.duration_ms, "number");
    }
    const control = requireCase(bundle, "ctrl-hidden-branch-and-or-clean");
    assert.equal(control.evidence_kind, "control");
    assert.deepEqual(
      control.records.map((record) => record.view.predicate),
      ["AND", "OR"],
    );
  });

  it("exports explicit skip reasons for unsupported families", () => {
    const ids = [
      "skip-android-emulator",
      "skip-real-proof-crypto",
      "skip-hidden-branch-circuit",
      "skip-generic-prover-lifecycle",
      "skip-wallet-consent-credential-probing",
      "skip-authenticated-verifier-origin-binding",
    ];
    for (const id of ids) {
      const item = requireCase(bundle, id);
      assert.equal(typeof item.skip_reason, "string");
      assert.ok(item.skip_reason.length > 8);
    }
  });

  it("analyze_campaign on collected traces has no pointer/context false positives", () => {
    const py = [
      "import json, sys",
      `sys.path.insert(0, ${JSON.stringify(HARNESS)})`,
      "from privacy_campaign import analyze_campaign",
      "print(json.dumps(analyze_campaign(json.load(sys.stdin))))",
    ].join("\n");
    const result = spawnSync("python3", ["-c", py], {
      input: JSON.stringify(bundle),
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.schema, "swiyu.privacy-campaign.v1");
    for (const finding of report.privacy.findings) {
      assert.equal(FORBIDDEN_KINDS.has(finding.kind), false, JSON.stringify(finding));
    }
    const remaining = report.privacy.findings.filter(
      (finding) => finding.kind !== "exploratory_distinguishability",
    );
    assert.equal(remaining.length, 2, JSON.stringify(remaining));
    const packagingFinding = remaining.find((finding) => finding.case_id === "sidecar-dist-entry-instanceof");
    const statusFinding = remaining.find((finding) => finding.case_id === "status-list-authoritative-subject-uri");
    assert.equal(packagingFinding.kind, "functional_difference");
    assert.equal(statusFinding.kind, "secret_disclosure");
    assert.equal(statusFinding.field, "/subject");
    assert.equal(statusFinding.observer, "authoritative SDK projection consumer");
    const packaging = report.privacy.cases.find((item) => item.id === "sidecar-dist-entry-instanceof");
    assert.equal(packaging.status, "findings");
  });

  it("prints one JSON bundle on stdout when executed", () => {
    const result = spawnSync(process.execPath, [COLLECTOR], {
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.equal(result.status, 0, result.stderr);
    const parsed = JSON.parse(result.stdout);
    assert.equal(parsed.provider.id, "swiyu-zkid-integration");
    assert.ok(parsed.cases.length >= 8);
  });
});
