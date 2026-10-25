// Operacje na bajtach wspólne dla modułów kryptograficznych sejfu.

export const utf8 = (text) => new TextEncoder().encode(text);

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export async function sha256Hex(bytes) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

// UUID z 16 bajtów nagłówka koperty (InterviewKey.id / ClinicKey.id), postać jak str(uuid) w Pythonie.
export function bytesToUuid(bytes) {
  if (bytes.length !== 16) throw new RangeError(`UUID: oczekiwano 16 B, jest ${bytes.length}`);
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export const random = (n) => crypto.getRandomValues(new Uint8Array(n));
