// Decision-pack verification and snapshot replay safety (Faz D slice 3),
// ported from open-evidence-verification decision_pack.py / pack_verifier.py
// / replay.py semantics. Integrity only: a pack verdict NEVER depends on
// rule outcomes, and replay never re-executes rules.
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import { canonicalizeJson, type JsonValue } from "./canonical.ts";
import { sha256Formatted } from "./receipt.ts";
import { isDsseEnvelope, parseDsse, preAuthenticationEncoding, type TrustedKey } from "./dsse.ts";

export interface PackVerification {
  overall: "PACK_VALID" | "PACK_INVALID";
  signature_state:
    | "SIGNATURE_NOT_PRESENT"
    | "SIGNATURE_VALID"
    | "SIGNATURE_INVALID"
    | "SIGNATURE_KEY_UNKNOWN";
  manifest_signature_check: "NOT_APPLICABLE" | "PASS" | "FAIL";
  reasons: string[];
  recomputed_pack_digest: string | null;
}

export type ReplayStatus =
  | "REPLAY_OK"
  | "PACK_INVALID"
  | "PACK_HASH_CHANGED"
  | "SNAPSHOT_INVALID"
  | "SNAPSHOT_LEAK";

const SPEC_VERSION = "oev-decision-pack/0.2";

function memberNameIsSafe(path: string): boolean {
  if (!path || path.includes("\x00") || path.includes("\\")) return false;
  if (path.startsWith("/")) return false;
  const parts = path.split("/");
  return !parts.some((p) => p === "" || p === "." || p === "..");
}

// sha256 over JCS of the manifest body WITHOUT pack_digest
// (decision_pack.py compute_pack_digest).
export function computePackDigest(manifest: Record<string, unknown>): string {
  const body: Record<string, JsonValue> = { ...manifest } as Record<string, JsonValue>;
  delete body["pack_digest"];
  return sha256Formatted(Buffer.from(canonicalizeJson(body as JsonValue), "utf8"));
}

export function verifyPackDir(packDir: string, trustedKeys: TrustedKey[] | null): PackVerification {
  const reasons: string[] = [];
  const fail = (
    overall: PackVerification["overall"],
    signature_state: PackVerification["signature_state"],
    check: PackVerification["manifest_signature_check"],
    recomputed: string | null,
  ): PackVerification => ({ overall, signature_state, manifest_signature_check: check, reasons, recomputed_pack_digest: recomputed });

  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(readFileSync(join(packDir, "manifest.json"), "utf8"));
  } catch (exc) {
    reasons.push(`manifest unreadable: ${(exc as Error).message}`);
    return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", null);
  }
  if (manifest["protocol_version"] !== SPEC_VERSION) {
    reasons.push(`unsupported protocol_version: ${JSON.stringify(manifest["protocol_version"])}`);
    return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", null);
  }
  const members = Array.isArray(manifest["members"]) ? (manifest["members"] as Record<string, unknown>[]) : [];
  if (members.length === 0) {
    reasons.push("manifest declares no members");
    return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", null);
  }
  for (const member of members) {
    const path = String(member["path"]);
    if (!memberNameIsSafe(path)) {
      reasons.push(`unsafe member path: ${path}`);
      return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", null);
    }
    const file = join(packDir, path);
    if (!existsSync(file)) {
      reasons.push(`missing member: ${path}`);
      return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", null);
    }
    const digest = sha256Formatted(readFileSync(file));
    if (digest !== String(member["sha256"]).toLowerCase()) {
      reasons.push(`digest mismatch: ${path}`);
      return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", null);
    }
  }
  const recomputed = computePackDigest(manifest);
  if (recomputed !== String(manifest["pack_digest"])) {
    reasons.push("manifest self-digest (pack_digest) does not match its body");
    return fail("PACK_INVALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", recomputed);
  }

  // Signature state: an unsigned pack is never invalid; a present signature
  // must verify against caller keys, and the signed payload must be the
  // exact manifest.json bytes.
  const sigPath = join(packDir, "manifest.dsse.json");
  if (!existsSync(sigPath)) {
    return fail("PACK_VALID", "SIGNATURE_NOT_PRESENT", "NOT_APPLICABLE", recomputed);
  }
  let envelope: Record<string, unknown>;
  try {
    envelope = JSON.parse(readFileSync(sigPath, "utf8"));
  } catch (exc) {
    reasons.push(`manifest.dsse.json unreadable: ${(exc as Error).message}`);
    return fail("PACK_VALID", "SIGNATURE_INVALID", "FAIL", recomputed);
  }
  if (!isDsseEnvelope(envelope)) {
    reasons.push("manifest.dsse.json is not a DSSE envelope");
    return fail("PACK_VALID", "SIGNATURE_INVALID", "FAIL", recomputed);
  }
  const parsed = parseDsse(envelope);
  const manifestBytes = readFileSync(join(packDir, "manifest.json"));
  if (!parsed.payload.equals(manifestBytes)) {
    reasons.push("signed payload does not match manifest.json bytes");
    return fail("PACK_VALID", "SIGNATURE_INVALID", "FAIL", recomputed);
  }
  if (!trustedKeys || trustedKeys.length === 0) {
    return fail("PACK_VALID", "SIGNATURE_KEY_UNKNOWN", "NOT_APPLICABLE", recomputed);
  }
  const pae = preAuthenticationEncoding(parsed);
  const verified = trustedKeys.some((key) => {
    try {
      return parsed.signatures.some((sig) => cryptoVerify(null, pae, createPublicKey(key.public_key_pem), sig.sig));
    } catch {
      return false;
    }
  });
  if (!verified) {
    reasons.push("manifest signature did not verify against caller trust roots");
    return fail("PACK_VALID", "SIGNATURE_INVALID", "FAIL", recomputed);
  }
  return fail("PACK_VALID", "SIGNATURE_VALID", "PASS", recomputed);
}

export interface ReplayResult {
  replay_status: ReplayStatus;
  reasons: string[];
  eligible_fact_ids: string[];
}

// Snapshot replay safety: digest pinning + snapshot-boundary coherence.
// NEVER re-executes rules; eligibility is computed from recorded times only.
export function replayPackDir(
  packDir: string,
  pin: Record<string, unknown> | null,
  trustedKeys: TrustedKey[] | null,
): ReplayResult {
  const verification = verifyPackDir(packDir, trustedKeys);
  if (verification.overall !== "PACK_VALID") {
    return { replay_status: "PACK_INVALID", reasons: verification.reasons, eligible_fact_ids: [] };
  }
  const recomputed = verification.recomputed_pack_digest as string;
  if (pin && String(pin["pack_digest"]) !== recomputed) {
    return {
      replay_status: "PACK_HASH_CHANGED",
      reasons: ["recomputed pack digest differs from the caller pin"],
      eligible_fact_ids: [],
    };
  }

  let snapshot: Record<string, unknown>;
  let facts: Record<string, unknown>;
  let runs: Record<string, unknown>;
  try {
    snapshot = JSON.parse(readFileSync(join(packDir, "snapshot_context.json"), "utf8"));
    facts = JSON.parse(readFileSync(join(packDir, "facts.json"), "utf8"));
    runs = JSON.parse(readFileSync(join(packDir, "rule_runs.json"), "utf8"));
  } catch (exc) {
    return { replay_status: "SNAPSHOT_INVALID", reasons: [(exc as Error).message], eligible_fact_ids: [] };
  }
  const capturedRaw = String(snapshot["captured_at"] ?? "");
  const capturedMs = Date.parse(capturedRaw);
  if (!Number.isFinite(capturedMs) || !capturedRaw.endsWith("Z")) {
    return {
      replay_status: "SNAPSHOT_INVALID",
      reasons: [`Snapshot captured_at is not a strict UTC timestamp: ${capturedRaw}`],
      eligible_fact_ids: [],
    };
  }
  const sourceIds = new Set(
    (Array.isArray(snapshot["sources"]) ? (snapshot["sources"] as Record<string, unknown>[]) : [])
      .map((s) => String(s["source_id"])),
  );

  const eligible: string[] = [];
  const excludedAfterCapture = new Set<string>();
  const factList = Array.isArray(facts["facts"]) ? (facts["facts"] as Record<string, unknown>[]) : [];
  for (const fact of factList) {
    const factId = String(fact["fact_id"]);
    const sourceId = fact["snapshot_source_id"];
    if (sourceId === null || sourceId === undefined) continue;
    if (!sourceIds.has(String(sourceId))) continue;
    const observedMs = Date.parse(String(fact["observed_at"] ?? ""));
    if (!Number.isFinite(observedMs)) continue;
    if (observedMs > capturedMs) {
      excludedAfterCapture.add(factId);
      continue;
    }
    eligible.push(factId);
  }

  let leak = false;
  const runList = Array.isArray(runs["rule_runs"]) ? (runs["rule_runs"] as Record<string, unknown>[]) : [];
  for (const run of runList) {
    const inputs = Array.isArray(run["inputs"]) ? run["inputs"].map(String) : [];
    if (inputs.some((fid) => excludedAfterCapture.has(fid))) leak = true;
  }
  return {
    replay_status: leak ? "SNAPSHOT_LEAK" : "REPLAY_OK",
    reasons: leak ? ["a rule run consumed post-snapshot evidence"] : [],
    eligible_fact_ids: eligible,
  };
}
