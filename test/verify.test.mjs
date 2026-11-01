import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { canonicalizeJson, CanonicalizationError } from "../src/canonical.ts";
import { verifyBundle } from "../src/verify.ts";
import { readCentralDirectory } from "../src/zip.ts";

const FIX = new URL("./fixtures/", import.meta.url).pathname;

test("JCS parity with the Python reference (RFC 8785)", () => {
  const parity = JSON.parse(readFileSync(`${FIX}jcs-parity.json`, "utf8"));
  for (const pair of parity.pairs) {
    assert.equal(canonicalizeJson(pair.input), pair.expected, JSON.stringify(pair.input));
  }
});

test("JCS rejects the non-canonical domain fail-closed", () => {
  assert.throws(() => canonicalizeJson(1.5), CanonicalizationError);
  assert.throws(() => canonicalizeJson(2 ** 53), CanonicalizationError);
  assert.throws(() => canonicalizeJson({ k: 1.25 }), CanonicalizationError);
});

test("manifest.json in the signed fixture is byte-identical to its JCS form", () => {
  const zip = readFileSync(`${FIX}valid-signed.zip`);
  const manifest = readCentralDirectory(zip).find((m) => m.name === "manifest.json");
  assert.ok(manifest);
  const parsed = JSON.parse(manifest.data.toString("utf8"));
  assert.equal(canonicalizeJson(parsed), manifest.data.toString("utf8"));
});

test("signed bundle verifies against caller trust roots", () => {
  const zip = readFileSync(`${FIX}valid-signed.zip`);
  const keys = JSON.parse(readFileSync(`${FIX}trust-keys.json`, "utf8"));
  const result = verifyBundle(zip, keys);
  assert.equal(result.status, "VALID_SIGNED");
});

test("tampered package fails with HASH_MISMATCH", () => {
  const zip = readFileSync(`${FIX}tampered.zip`);
  const result = verifyBundle(zip, null);
  assert.equal(result.status, "HASH_MISMATCH");
});

test("traversal member is refused (UNSAFE_ARCHIVE)", () => {
  const zip = readFileSync(`${FIX}traversal.zip`);
  const result = verifyBundle(zip, null);
  assert.equal(result.status, "UNSAFE_ARCHIVE");
  assert.ok(result.notes.some((n) => n.includes("..")));
});

test("duplicate member is refused (UNSAFE_ARCHIVE)", () => {
  const zip = readFileSync(`${FIX}duplicate.zip`);
  const result = verifyBundle(zip, null);
  assert.equal(result.status, "UNSAFE_ARCHIVE");
  assert.ok(result.notes.some((n) => n.includes("duplicate")));
});

test("tiny archive-size limit refuses before reading", () => {
  const zip = readFileSync(`${FIX}valid-signed.zip`);
  const result = verifyBundle(zip, null, { ...verifyBundleOptions(), maxArchiveBytes: 10 });
  assert.equal(result.status, "UNSAFE_ARCHIVE");
});

function verifyBundleOptions() {
  // Placeholder kept for readability; defaults come from the module.
  return { maxArchiveBytes: 512 * 1024 * 1024, maxEntries: 10000, maxTotalUncompressedBytes: 512 * 1024 * 1024, maxSingleMemberBytes: 64 * 1024 * 1024 };
}
