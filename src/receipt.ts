// Receipt self-digest and DSSE unwrapping, mirroring
// open-evidence-verification src/oev/receipts.py: the digest is computed
// over the canonicalized receipt body WITHOUT the receipt_digest field,
// and is formatted as "sha256:<hex>".
import { createHash } from "node:crypto";
import { canonicalizeJson, type JsonValue } from "./canonical.ts";
import { isDsseEnvelope, parseDsse } from "./dsse.ts";

export function sha256Formatted(data: Buffer | string): string {
  return `sha256:${createHash("sha256").update(data).digest("hex")}`;
}

export function unwrapReceipt(data: Record<string, unknown>): {
  receipt: Record<string, unknown>;
  isDsse: boolean;
} {
  if (isDsseEnvelope(data)) {
    const envelope = parseDsse(data);
    return { receipt: JSON.parse(envelope.payload.toString("utf8")), isDsse: true };
  }
  return { receipt: data, isDsse: false };
}

export function computeReceiptDigest(receipt: Record<string, unknown>): string {
  const body: Record<string, JsonValue> = { ...receipt } as Record<string, JsonValue>;
  delete body["receipt_digest"];
  return sha256Formatted(Buffer.from(canonicalizeJson(body as JsonValue), "utf8"));
}

export function verifyReceiptSelfDigest(receipt: Record<string, unknown>): boolean {
  const declared = typeof receipt["receipt_digest"] === "string" ? receipt["receipt_digest"] : "";
  return declared === computeReceiptDigest(receipt);
}
