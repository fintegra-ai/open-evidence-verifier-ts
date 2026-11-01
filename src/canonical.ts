// RFC 8785 (JCS) canonicalization for the I-JSON domain OEPT admits:
// null, booleans, strings, integers with |n| <= 2**53 - 1, arrays, and
// objects with string keys. Anything else (floats, huge ints, lone
// surrogates) MUST be rejected, never coerced - mirroring the Python
// reference (oept/canonical.py).
export class CanonicalizationError extends Error {}

export type JsonValue =
  | null
  | boolean
  | string
  | number
  | JsonValue[]
  | { [key: string]: JsonValue };

function checkDomain(value: unknown, path: string): void {
  if (value === null) return;
  const t = typeof value;
  if (t === "boolean") return;
  if (t === "string") {
    // I-JSON: no unpaired surrogates (well-formed stringify would mask them).
    if (/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(value as string)) {
      throw new CanonicalizationError(`${path}: unpaired surrogate is not I-JSON`);
    }
    return;
  }
  if (t === "number") {
    const n = value as number;
    if (!Number.isInteger(n) || Math.abs(n) > 2 ** 53 - 1) {
      throw new CanonicalizationError(`${path}: number is outside the exact JCS integer domain`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => checkDomain(item, `${path}[${i}]`));
    return;
  }
  if (t === "object") {
    for (const [key, item] of Object.entries(value as { [k: string]: JsonValue })) {
      checkDomain(item, `${path}.${key}`);
    }
    return;
  }
  throw new CanonicalizationError(`${path}: type ${t} is not in the canonical domain`);
}

function sortValue(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value !== null && typeof value === "object") {
    const out: { [key: string]: JsonValue } = {};
    // Array.prototype.sort orders by UTF-16 code units, which is exactly
    // the JCS key ordering rule.
    for (const key of Object.keys(value).sort()) {
      out[key] = sortValue(value[key]);
    }
    return out;
  }
  return value;
}

export function canonicalizeJson(value: JsonValue): string {
  checkDomain(value, "$");
  return JSON.stringify(sortValue(value));
}
