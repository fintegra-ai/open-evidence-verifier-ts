// External-verifier contract (Faz D slice 1): reads one OEVP conformance
// vector input.json and prints the observation JSON for the runner.
// Supported action: "verify". Any other action reports unsupported
// (fail-closed, never a silent pass).
//
// Usage: node dist/cli.js <input.json>
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { verifyBundle, type TrustedKey } from "./verify.ts";

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

const inputPath = resolve(process.argv[2] ?? "");
const vector: VectorInput = JSON.parse(readFileSync(inputPath, "utf8"));
// input.json lives at <repo>/conformance/vectors/<id>/input.json.
const repoRoot = resolve(dirname(inputPath), "..", "..", "..");

if (vector.action !== "verify") {
  emit({
    vector_id: vector.vector_id,
    exit_code: null,
    result: {},
    unsupported: `action '${vector.action}' is not implemented in slice 1`,
  });
  process.exit(0);
}

const emitUnsupported = (exc: unknown): void => {
  emit({
    vector_id: vector.vector_id,
    exit_code: null,
    result: {},
    error: exc instanceof Error ? exc.message : String(exc),
  });
  process.exit(0);
};

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
