// Minimal ZIP central-directory reader (read-only). Stdlib only:
// node:zlib.inflateRawSync for method 8, raw for method 0 (stored).
// Local headers are never trusted for sizes - the central directory is
// authoritative; only the local name/extra lengths are used to locate data.
import { inflateRawSync } from "node:zlib";

export interface ZipMember {
  name: string;
  data: Buffer;
  externalAttr: number;
}

export class ZipFormatError extends Error {}

export function readCentralDirectory(buf: Buffer): ZipMember[] {
  let eocd = -1;
  const searchFloor = Math.max(0, buf.length - 22 - 65535);
  for (let i = buf.length - 22; i >= searchFloor; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipFormatError("end of central directory not found");

  const count = buf.readUInt16LE(eocd + 10);
  let ptr = buf.readUInt32LE(eocd + 16);
  const members: ZipMember[] = [];
  for (let i = 0; i < count; i++) {
    if (ptr + 46 > buf.length || buf.readUInt32LE(ptr) !== 0x02014b50) {
      throw new ZipFormatError("bad central directory entry");
    }
    const method = buf.readUInt16LE(ptr + 10);
    const compressedSize = buf.readUInt32LE(ptr + 20);
    const nameLen = buf.readUInt16LE(ptr + 28);
    const extraLen = buf.readUInt16LE(ptr + 30);
    const commentLen = buf.readUInt16LE(ptr + 32);
    const externalAttr = buf.readUInt32LE(ptr + 38);
    const localOffset = buf.readUInt32LE(ptr + 42);
    const name = buf.subarray(ptr + 46, ptr + 46 + nameLen).toString("utf8");

    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== 0x04034b50) {
      throw new ZipFormatError(`bad local header for ${name}`);
    }
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    if (dataStart + compressedSize > buf.length) {
      throw new ZipFormatError(`member data out of bounds: ${name}`);
    }
    const raw = buf.subarray(dataStart, dataStart + compressedSize);
    let data: Buffer;
    if (method === 0) {
      data = Buffer.from(raw);
    } else if (method === 8) {
      data = inflateRawSync(raw);
    } else {
      throw new ZipFormatError(`unsupported compression method ${method} for ${name}`);
    }
    members.push({ name, data, externalAttr });
    ptr += 46 + nameLen + extraLen + commentLen;
  }
  return members;
}
