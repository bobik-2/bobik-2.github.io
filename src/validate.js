// Walidacja argumentów operacji (spec B, „Walidacja argumentów"): każdy błąd = bad_args.
import { B64Error, fromB64url } from "./b64.js";
import { VaultError } from "./errors.js";

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const FIELD_RE = /^[a-z_]+\.[A-Za-z]+\.[a-z0-9_]+$/;

const bad = () => new VaultError("bad_args");

export function posInt(v) {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= 0) throw bad();
  return v;
}

export const optPosInt = (v) => (v === null ? null : posInt(v));

export function uuid(v) {
  if (typeof v !== "string" || !UUID_RE.test(v)) throw bad();
  return v;
}

export function field(v) {
  if (typeof v !== "string" || v.length > 200 || !FIELD_RE.test(v)) throw bad();
  return v;
}

export function text(v, max) {
  if (typeof v !== "string" || v.length < 1 || v.length > max) throw bad();
  return v;
}

export function oneOf(v, allowed) {
  if (!allowed.includes(v)) throw bad();
  return v;
}

export function bytes(v, { min = 1, max }) {
  let out;
  try {
    out = fromB64url(v);
  } catch (e) {
    // B64Error: nie tekst, znak spoza alfabetu base64url, padding albo długość 4k+1 (F8).
    if (e instanceof B64Error) throw bad();
    throw e;
  }
  if (out.length < min || out.length > max) throw bad();
  return out;
}

export function list(v, { min = 0, max }, each) {
  if (!Array.isArray(v) || v.length < min || v.length > max) throw bad();
  return v.map((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw bad();
    return each(item);
  });
}
