import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { unwrapReceipt, verifyReceiptSelfDigest } from "../src/receipt.ts";
import { evaluateReceiptTrust, parseDsse } from "../src/dsse.ts";

const REPO = new URL("..", import.meta.url).pathname;
const CLI = join(REPO, "src", "cli.ts");
// The sibling OEVP repository's conformance fixtures (read-only inputs).
const OEVP_FIX = resolve(REPO, "..", "open-evidence-verification", "conformance", "fixtures");

function runCli(inputObj) {
  const dir = mkdtempSync(join(tmpdir(), "oepts2-"));
  const vectorsDir = join(dir, "conformance", "vectors", "01-x");
  mkdirSync(vectorsDir, { recursive: true });
  const inputPath = join(vectorsDir, "input.json");
  writeFileSync(inputPath, JSON.stringify(inputObj));
  const stdout = execFileSync("node", [CLI, inputPath], { encoding: "utf8" });
  return JSON.parse(stdout.trim());
}

test("receipt self-digest: genuine payload verifies, tampered does not", () => {
  const env = JSON.parse(readFileSync(`${OEVP_FIX}/05-reverify-package-mismatch/receipt.dsse.json`, "utf8"));
  const { receipt } = unwrapReceipt(env);
  assert.equal(verifyReceiptSelfDigest(receipt), true);
  const tampered = { ...receipt, receipt_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" };
  assert.equal(verifyReceiptSelfDigest(tampered), false);
});

test("DSSE trust evaluation matches the Python reference", () => {
  const env = parseDsse(
    JSON.parse(readFileSync(`${OEVP_FIX}/05-reverify-package-mismatch/receipt.dsse.json`, "utf8")),
  );
  const keys = JSON.parse(readFileSync(`${OEVP_FIX}/01-valid-oept-pass/verifier-trust-keys.json`, "utf8"));
  const evaluation = evaluateReceiptTrust(env, keys);
  assert.equal(evaluation.crypto_valid, true);
  assert.equal(evaluation.is_trusted, true);
  assert.equal(evaluation.trusted_key_id, "test-verifier-2026");
  // Same envelope against an empty trust store: never trusted.
  const untrusted = evaluateReceiptTrust(env, []);
  assert.deepEqual(untrusted, { crypto_valid: false, is_trusted: false, trusted_key_id: null });
});

test("inspect_receipt action: tampered receipt fails all three (vector 04)", () => {
  const out = runCli({
    vector_id: "04-tampered-receipt",
    action: "inspect_receipt",
    inputs: {
      receipt: `${OEVP_FIX}/04-tampered-receipt/receipt.dsse.json`,
      verifier_keys: `${OEVP_FIX}/04-tampered-receipt/verifier-trust-keys.json`,
    },
  });
  assert.equal(out.exit_code, 1);
  assert.equal(out.result.receipt_digest_valid, false);
  assert.equal(out.result.crypto_valid, false);
  assert.equal(out.result.is_trusted_signer, false);
});

test("reverify action: package mismatch fails closed (vector 05)", () => {
  const out = runCli({
    vector_id: "05-reverify-package-mismatch",
    action: "reverify",
    inputs: {
      package: `${OEVP_FIX}/05-reverify-package-mismatch/package.zip`,
      profile: `${OEVP_FIX}/05-reverify-package-mismatch/profile.json`,
      receipt: `${OEVP_FIX}/05-reverify-package-mismatch/receipt.dsse.json`,
    },
  });
  assert.equal(out.exit_code, 2);
  assert.equal(out.result.reverification_result, "MISMATCH");
  assert.equal(out.result.package_digest_match, false);
  assert.deepEqual(out.result.fresh_checks, []);
});
