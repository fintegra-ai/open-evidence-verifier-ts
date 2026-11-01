// External-verifier contract (Faz D): reads one OEVP conformance vector
// input.json and prints the observation JSON for the runner. Supported
// actions: "verify", "inspect_receipt", "reverify" (fail-closed prefix:
// self-digest then package digest), and the pack family "pack_verify" /
// "pack_replay" / "pack_receipt_verify" (integrity + replay safety; rules
// are NEVER re-executed). Anything else reports exit_code null (never a
// silent pass).
//
// Usage: node src/cli.ts <input.json>
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { verifyBundle, type TrustedKey } from "./verify.ts";
import {
  evaluateReceiptTrust,
  isDsseEnvelope,
  parseDsse,
} from "./dsse.ts";
import { sha256Formatted, unwrapReceipt, verifyReceiptSelfDigest } from "./receipt.ts";
import { computePackDigest, replayPackDir, verifyPackDir } from "./pack.ts";
import { join } from "node:path";

interface VectorInput {
  vector_id: string;
  action: string;
  inputs: Record<string, string>;
  source_fixture?: string;
}

interface CheckOutcome {
  check_id: string;
  category: string;
  status: string;
  detail: string;
  duration_ms: number;
}

function emit(payload: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(payload) + "\n");
}

function emitError(exc: unknown): void {
  emit({
    vector_id: (typeof vector === "object" && vector?.vector_id) || null,
    exit_code: null,
    result: {},
    error: exc instanceof Error ? exc.message : String(exc),
  });
  process.exit(0);
}

const inputPath = resolve(process.argv[2] ?? "");
const vector: VectorInput = JSON.parse(readFileSync(inputPath, "utf8"));
// input.json lives at <repo>/conformance/vectors/<id>/input.json.
const repoRoot = resolve(dirname(inputPath), "..", "..", "..");

if (vector.action === "inspect_receipt") {
  const receiptData = JSON.parse(
    readFileSync(resolve(repoRoot, vector.inputs["receipt"] ?? ""), "utf8"),
  ) as Record<string, unknown>;
  const verifierKeys: TrustedKey[] | null = vector.inputs["verifier_keys"]
    ? JSON.parse(readFileSync(resolve(repoRoot, vector.inputs["verifier_keys"]), "utf8"))
    : null;
  const { receipt, isDsse } = unwrapReceipt(receiptData);
  const digestValid = verifyReceiptSelfDigest(receipt);
  let cryptoValid = false;
  let isTrustedSigner = false;
  if (isDsse && isDsseEnvelope(receiptData)) {
    // Mirrors trust.py evaluate_receipt_trust: trust evaluation only against
    // caller-supplied keys; no keys -> cannot be trusted.
    const evaluation = evaluateReceiptTrust(parseDsse(receiptData), verifierKeys);
    cryptoValid = evaluation.crypto_valid;
    isTrustedSigner = evaluation.is_trusted;
  }
  emit({
    vector_id: vector.vector_id,
    exit_code: digestValid ? 0 : 1,
    result: { receipt_digest_valid: digestValid, crypto_valid: cryptoValid, is_trusted_signer: isTrustedSigner },
  });
  process.exit(0);
}

if (vector.action === "reverify") {
  // Slice 2 implements the fail-closed prefix of the pipeline (self-digest,
  // then package digest). If both match, fresh execution is slice 3 and is
  // reported as unsupported rather than guessed.
  try {
    const receiptData = JSON.parse(
      readFileSync(resolve(repoRoot, vector.inputs["receipt"] ?? ""), "utf8"),
    ) as Record<string, unknown>;
    const { receipt } = unwrapReceipt(receiptData);
    const mismatch = (): void => {
      emit({
        vector_id: vector.vector_id,
        exit_code: 2,
        result: {
          reverification_result: "MISMATCH",
          package_digest_match: false,
          profile_digest_match: false,
          fresh_checks: [],
        },
      });
      process.exit(0);
    };
    if (!verifyReceiptSelfDigest(receipt)) {
      mismatch();
    }
    const packageBytes = readFileSync(resolve(repoRoot, vector.inputs["package"] ?? ""));
    const recordedPackageDigest = (receipt["package"] as Record<string, unknown> | undefined)?.["digest"];
    if (sha256Formatted(packageBytes) !== String(recordedPackageDigest)) {
      mismatch();
    }
    emit({
      vector_id: vector.vector_id,
      exit_code: null,
      result: {},
      unsupported: "package and self-digest matched; fresh re-execution pipeline is not implemented in slice 2",
    });
    process.exit(0);
  } catch (exc) {
    emitError(exc);
  }
}

if (vector.action === "pack_verify") {
  try {
    const keys: TrustedKey[] | null = vector.inputs["pack_verifier_keys"]
      ? JSON.parse(readFileSync(resolve(repoRoot, vector.inputs["pack_verifier_keys"]), "utf8"))
      : null;
    const verification = verifyPackDir(resolve(repoRoot, vector.inputs["pack"] ?? ""), keys);
    // Mirror cmd_pack_verify: invalid pack -> 1; pinned keys with an
    // invalid/unknown signature -> 2; otherwise 0.
    let exit_code = 0;
    if (verification.overall !== "PACK_VALID") exit_code = 1;
    else if (keys && verification.signature_state !== "SIGNATURE_VALID" && verification.signature_state !== "SIGNATURE_NOT_PRESENT") exit_code = 2;
    emit({
      vector_id: vector.vector_id,
      exit_code,
      result: { overall: verification.overall, signature_state: verification.signature_state },
    });
    process.exit(0);
  } catch (exc) {
    emitError(exc);
  }
}

if (vector.action === "pack_replay") {
  try {
    const pin: Record<string, unknown> | null = vector.inputs["pin"]
      ? JSON.parse(readFileSync(resolve(repoRoot, vector.inputs["pin"]), "utf8"))
      : null;
    const replay = replayPackDir(resolve(repoRoot, vector.inputs["pack"] ?? ""), pin, null);
    const exitMap: Record<string, number> = { REPLAY_OK: 0, PACK_INVALID: 1 };
    emit({
      vector_id: vector.vector_id,
      exit_code: exitMap[replay.replay_status] ?? 2,
      result: { replay_status: replay.replay_status },
    });
    process.exit(0);
  } catch (exc) {
    emitError(exc);
  }
}

if (vector.action === "pack_receipt_verify") {
  try {
    const receipt = JSON.parse(
      readFileSync(resolve(repoRoot, vector.inputs["pack_receipt"] ?? ""), "utf8"),
    ) as Record<string, unknown>;
    const digestValid = verifyReceiptSelfDigest(receipt);
    let packBinding = "PACK_BINDING_MISMATCH";
    if (vector.inputs["pack"]) {
      const manifest = JSON.parse(
        readFileSync(join(resolve(repoRoot, vector.inputs["pack"]), "manifest.json"), "utf8"),
      ) as Record<string, unknown>;
      const recomputed = computePackDigest(manifest);
      packBinding = recomputed === String(receipt["pack_digest"]) ? "PACK_BINDING_MATCH" : "PACK_BINDING_MISMATCH";
    }
    const overall = digestValid && packBinding === "PACK_BINDING_MATCH" ? "RECEIPT_VALID" : "RECEIPT_INVALID";
    emit({
      vector_id: vector.vector_id,
      exit_code: overall === "RECEIPT_VALID" ? 0 : 1,
      result: { overall, receipt_digest_valid: digestValid, pack_binding: packBinding },
    });
    process.exit(0);
  } catch (exc) {
    emitError(exc);
  }
}

if (vector.action !== "verify") {
  emit({
    vector_id: vector.vector_id,
    exit_code: null,
    result: {},
    unsupported: `action '${vector.action}' is not implemented in slice 1`,
  });
  process.exit(0);
}

try {
  const zipBytes = readFileSync(resolve(repoRoot, vector.inputs["package"] ?? ""));
  const profile = JSON.parse(readFileSync(resolve(repoRoot, vector.inputs["profile"] ?? ""), "utf8"));
  const trustedKeys: TrustedKey[] | null = vector.inputs["package_trust_keys"]
    ? JSON.parse(readFileSync(resolve(repoRoot, vector.inputs["package_trust_keys"]), "utf8"))
    : null;

  const result = verifyBundle(zipBytes, trustedKeys);
  const requested = new Set([
    ...(profile.required_checks ?? []),
    ...(profile.optional_checks ?? []),
  ]);

  const checks: CheckOutcome[] = [];
  const push = (checkId: string, category: string, status: string, detail: string): void => {
    checks.push({ check_id: checkId, category, status, detail, duration_ms: 0 });
  };

  const structuralFailure =
    result.status === "UNSAFE_ARCHIVE" || result.status === "MALFORMED_BUNDLE" ||
    result.status === "UNSUPPORTED_SPEC_VERSION";
  const integrityFailure =
    result.status === "HASH_MISMATCH" || result.status === "MISSING_FILE" ||
    result.status === "UNEXPECTED_FILE";

  if (requested.has("archive_safety")) {
    push(
      "archive_safety",
      "safety",
      result.status === "UNSAFE_ARCHIVE" ? "FAIL" : "PASS",
      result.status === "UNSAFE_ARCHIVE" ? result.notes.join("; ") : "Archive structure and member paths are safe",
    );
  }
  if (requested.has("manifest_structure")) {
    if (result.status === "UNSAFE_ARCHIVE") {
      push("manifest_structure", "structure", "NOT_RUN", "Archive safety check failed; manifest was not evaluated");
    } else if (structuralFailure) {
      push("manifest_structure", "structure", "FAIL", result.notes.join("; "));
    } else {
      push("manifest_structure", "structure", "PASS", `Manifest parsed successfully (spec: ${result.bundleSpecVersion})`);
    }
  }
  if (requested.has("member_digests")) {
    if (structuralFailure) {
      push("member_digests", "integrity", "NOT_RUN", "Prior structural check failed; member digests were not evaluated");
    } else if (integrityFailure) {
      push("member_digests", "integrity", "FAIL", result.notes.join("; "));
    } else {
      push("member_digests", "integrity", "PASS", "All declared member SHA-256 digests matched");
    }
  }
  if (requested.has("application_signature")) {
    if (structuralFailure || integrityFailure) {
      push("application_signature", "signature", "NOT_RUN", "Prior integrity or structural check failed; signature was not evaluated");
    } else if (result.status === "VALID_SIGNED") {
      push("application_signature", "signature", "PASS", "Valid Ed25519 signature verified against a trusted key");
    } else if (result.status === "SIGNATURE_INVALID") {
      push("application_signature", "signature", "FAIL", "Application signature is cryptographically invalid or does not match trusted key");
    } else {
      push("application_signature", "signature", "UNVERIFIED", "Package has no matching application signature (unsigned or unknown key)");
    }
  }
  for (const check of requested) {
    if (!["archive_safety", "manifest_structure", "member_digests", "application_signature"].includes(check)) {
      push(check, "unsupported", "UNSUPPORTED", `Check '${check}' is not supported by the TS verifier slice 1`);
    }
  }

  // Aggregation contract (open-evidence-verification receipts.py
  // aggregate_overall_result): required FAIL -> TECHNICAL_CHECKS_FAILED;
  // required NOT_RUN/NOT_APPLICABLE/UNVERIFIED/UNSUPPORTED ->
  // PROFILE_UNSATISFIED; all required PASS -> TECHNICAL_CHECKS_PASSED.
  const requiredIds = new Set(profile.required_checks ?? []);
  const requiredFails = checks.some((c) => requiredIds.has(c.check_id) && c.status === "FAIL");
  const requiredUnsatisfied = checks.some(
    (c) => requiredIds.has(c.check_id) && ["NOT_RUN", "NOT_APPLICABLE", "UNVERIFIED", "UNSUPPORTED"].includes(c.status),
  );
  const overall = requiredFails
    ? "TECHNICAL_CHECKS_FAILED"
    : requiredUnsatisfied
      ? "PROFILE_UNSATISFIED"
      : "TECHNICAL_CHECKS_PASSED";
  emit({
    vector_id: vector.vector_id,
    exit_code: overall === "TECHNICAL_CHECKS_PASSED" ? 0 : 2,
    result: { overall_result: overall, checks },
  });
  process.exit(0);
} catch (exc) {
  emitUnsupported(exc);
}
