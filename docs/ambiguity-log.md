# Ambiguity / Spec-Gap Log (Faz D)

Every spec gap discovered while implementing a second verifier from the
normative drafts goes here. Entries are numbered, reference the vector or
test that exposed them, and end with the resolution (spec clarification or
implementation fix). Kapı D closes only when this log stops growing.

## A-001 — Required-check UNVERIFIED is PROFILE_UNSATISFIED, not FAILED

- **Found**: 2026-11-01, OEVP conformance vector `03-required-signature-unsatisfied`.
- **Gap**: OEPT-1.0/OEVP-1.0 drafts did not state how the overall result is
  derived from per-check statuses. The TS slice-1 implementation guessed
  "any required check not PASS → TECHNICAL_CHECKS_FAILED"; the Python
  reference distinguishes FAIL (→ `TECHNICAL_CHECKS_FAILED`) from
  NOT_RUN/NOT_APPLICABLE/UNVERIFIED/UNSUPPORTED (→ `PROFILE_UNSATISFIED`).
- **Resolution**: aggregation contract is documented in
  `open-evidence-verification/src/oev/receipts.py::aggregate_overall_result`
  (docstring). TS verifier (`src/cli.ts`) now implements it. The
  distinction MUST be lifted into OEVP-1.0 §8 (error taxonomy) before 1.0.
