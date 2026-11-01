// Minimal DSSE v1 envelope parsing and Ed25519 trust evaluation, mirroring
// open-evidence-verification src/oev/dsse.py and src/oev/trust.py.
// Trust roots are caller-supplied only; a signed receipt from an unknown
// signer is NEVER trusted.
import { verify as cryptoVerify, createPublicKey } from "node:crypto";

export interface DsseSignature {
  keyid: string | null;
  sig: Buffer;
}

export interface DsseEnvelope {
  payloadType: string;
  payload: Buffer;
  signatures: DsseSignature[];
}

export class DsseFormatError extends Error {}

export function isDsseEnvelope(data: unknown): data is Record<string, unknown> {
  const d = data as Record<string, unknown>;
  return (
    typeof d === "object" &&
    d !== null &&
    "payloadType" in d &&
    "payload" in d &&
    "signatures" in d
  );
}

export function parseDsse(data: Record<string, unknown>): DsseEnvelope {
  const payloadType = data["payloadType"];
  if (typeof payloadType !== "string") throw new DsseFormatError("Envelope missing or invalid 'payloadType' string");
  const payloadB64 = data["payload"];
  if (typeof payloadB64 !== "string") throw new DsseFormatError("Envelope missing or invalid 'payload' string");
  if (!Array.isArray(data["signatures"]) || data["signatures"].length === 0) {
    throw new DsseFormatError("Envelope missing 'signatures' array");
  }
  const signatures: DsseSignature[] = (data["signatures"] as Record<string, unknown>[]).map((s) => ({
    keyid: typeof s["keyid"] === "string" ? s["keyid"] : null,
    sig: Buffer.from(String(s["sig"]), "base64"),
  }));
  return { payloadType, payload: Buffer.from(payloadB64, "base64"), signatures };
}

// DSSE v1 Pre-Authentication Encoding:
//   "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload
export function preAuthenticationEncoding(envelope: DsseEnvelope): Buffer {
  const type = Buffer.from(envelope.payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${type.length} `, "utf8"),
    type,
    Buffer.from(` ${envelope.payload.length} `, "utf8"),
    envelope.payload,
  ]);
}

export interface TrustEvaluation {
  crypto_valid: boolean;
  is_trusted: boolean;
  trusted_key_id: string | null;
}

export interface TrustedKey {
  key_id: string;
  public_key_pem: string;
}

// Mirrors trust.py evaluate_receipt_trust: the receipt is trusted only when
// its signature verifies against one of the CALLER-SUPPLIED keys.
export function evaluateReceiptTrust(envelope: DsseEnvelope, trustedKeys: TrustedKey[] | null): TrustEvaluation {
  if (!trustedKeys || trustedKeys.length === 0) {
    return { crypto_valid: false, is_trusted: false, trusted_key_id: null };
  }
  const pae = preAuthenticationEncoding(envelope);
  for (const key of trustedKeys) {
    try {
      const publicKey = createPublicKey(key.public_key_pem);
      for (const signature of envelope.signatures) {
        if (cryptoVerify(null, pae, publicKey, signature.sig)) {
          return { crypto_valid: true, is_trusted: true, trusted_key_id: key.key_id };
        }
      }
    } catch {
      // malformed key material: this trusted key cannot verify, continue
    }
  }
  return { crypto_valid: false, is_trusted: false, trusted_key_id: null };
}
