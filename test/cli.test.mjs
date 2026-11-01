import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const REPO = new URL("..", import.meta.url).pathname;
const CLI = join(REPO, "src", "cli.ts");
const FIX = new URL("./fixtures/", import.meta.url).pathname;

// Fixture profile for the verify contract (required check must all PASS for
// TECHNICAL_CHECKS_PASSED).
writeFileSync(
  `${FIX}profile.json`,
  JSON.stringify({
    protocol_version: "oev-profile/0.1",
    profile_id: "ts-slice1",
    profile_version: "0.1.0",
    target_format: "oept-bundle/0.1",
    required_checks: [
      "archive_safety",
      "manifest_structure",
      "member_digests",
      "application_signature",
    ],
  }),
);

function runCli(inputObj) {
  const dir = mkdtempSync(join(tmpdir(), "oepts-"));
  // The contract resolves member paths against the repo root three levels
  // above input.json; absolute paths pass through unchanged, so use them.
  const vectorsDir = join(dir, "conformance", "vectors", "01-x");
  mkdirSync(vectorsDir, { recursive: true });
  const inputPath = join(vectorsDir, "input.json");
  const absolute = {};
  for (const [k, v] of Object.entries(inputObj)) {
    absolute[k] = v.startsWith("/") ? v : resolve(FIX, v);
  }
  writeFileSync(
    inputPath,
    JSON.stringify({ vector_id: "test", action: inputObj.action ?? "verify", inputs: absolute }),
  );
  const stdout = execFileSync("node", [CLI, inputPath], { encoding: "utf8" });
  return JSON.parse(stdout.trim());
}

test("verify action on the signed fixture matches the OEVP contract", () => {
  const out = runCli({
    action: "verify",
    package: `${FIX}valid-signed.zip`,
    profile: `${FIX}profile.json`,
    package_trust_keys: `${FIX}trust-keys.json`,
  });
  assert.equal(out.vector_id, "test");
  assert.equal(out.exit_code, 0);
  assert.equal(out.result.overall_result, "TECHNICAL_CHECKS_PASSED");
  const byId = Object.fromEntries(out.result.checks.map((c) => [c.check_id, c.status]));
  assert.deepEqual(byId, {
    archive_safety: "PASS",
    manifest_structure: "PASS",
    member_digests: "PASS",
    application_signature: "PASS",
  });
});

test("unsupported actions report fail-closed, never a silent pass", () => {
  const out = runCli({ action: "pack_replay", package: `${FIX}valid-signed.zip` });
  assert.equal(out.exit_code, null);
  assert.equal(out.result && Object.keys(out.result).length, 0);
  assert.match(out.unsupported, /pack_replay/);
});

test("reverify with a missing receipt reports the error contract, not a crash", () => {
  const out = runCli({ action: "reverify", package: `${FIX}valid-signed.zip` });
  assert.equal(out.exit_code, null);
  assert.equal(out.result && Object.keys(out.result).length, 0);
  assert.ok(typeof out.error === "string" && out.error.length > 0);
});
