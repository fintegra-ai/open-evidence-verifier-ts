# open-evidence-verifier-ts (Faz D, slice 1-3)

TypeScript/Node implementation of the OEPT bundle verifier (Faz D of the
NLnet plan v2), written from the normative drafts — not a port of the
Python code. Stdlib-only, Node >= 23.6 (native type stripping).

## Status

- **12/12 OEVP conformance vectors pass with identical results to the
  Python reference** (acceptance: `run_vectors.py` external mode,
  see open-evidence-verification `spec/faz-d-ts-verifier-plan.md`).
- Supports: bundle verify (archive safety, digests, Ed25519), receipt
  inspect (self-digest + DSSE trust), reverify (fail-closed prefix),
  pack verify / replay safety / pack receipt verification.
- `docs/ambiguity-log.md` records every spec gap the second
  implementation exposed (Kapı D requirement).

## Usage

    node src/cli.ts <vector-input.json>

Prints one JSON object per the external-verifier contract:
`{"vector_id", "exit_code", "result"}`. Unsupported actions report
`exit_code: null` — never a silent pass.

## Honest boundaries

- Receipt authenticity is NOT established here — that is
  `oev receipt verify` with caller-pinned keys (OEVP).
- Rules are never re-executed; replay safety is digest/pinning only.
- npm publication and the final package name are pending owner decisions.
