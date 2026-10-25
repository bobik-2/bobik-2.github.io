// Wektory krzyżowe (spec B, „Wektory krzyżowe"): odczyt i gotowe argumenty protokołu.
// Używany przez Vitest i przez testy Playwright (proces Node).
import { readFileSync } from "node:fs";
import { fromB64url } from "../../src/b64.js";

const load = (name) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));

export const BOBIK2 = load("bobik2_v1.json");
export const loadSejf = () => load("sejf_v1.json");
export const b = (text) => fromB64url(text);

const P256 = { name: "ECDH", namedCurve: "P-256" };

export async function bobik2ClinicPair() {
  return {
    privateKey: await crypto.subtle.importKey("pkcs8", b(BOBIK2.clinic.private_key_pkcs8_der), P256, false, ["deriveBits"]),
    publicKey: await crypto.subtle.importKey("spki", b(BOBIK2.clinic.public_key_spki_der), P256, true, []),
  };
}

export function bobik2Interview() {
  return {
    interview_id: BOBIK2.interview_id,
    interview_key_id: BOBIK2.interview_key_id,
    clinic_key_id: BOBIK2.clinic_key_id,
    clinic_wrap: BOBIK2.clinic_wrap.blob,
  };
}

// Argumenty `open`: wszystkie pola z wektora, potem przypadki negatywne (kolejność = bobik2ExpectedValues).
export function bobik2OpenRequest() {
  const sealed = BOBIK2.sealed.map((s) => ({ kind: "sealed", interview_id: BOBIK2.interview_id, field: s.field, blob: s.blob }));
  const stc = BOBIK2.stc.map((s) => ({ kind: "stc", clinic_id: BOBIK2.clinic_id, field: s.field, blob: s.blob }));
  const negative = BOBIK2.negative.map((n) =>
    n.kind === "sealed"
      ? { kind: "sealed", interview_id: n.interview_id, field: n.field, blob: n.blob }
      : { kind: "stc", clinic_id: n.clinic_id, field: n.field, blob: n.blob },
  );
  return { interviews: [bobik2Interview()], items: [...sealed, ...stc, ...negative] };
}

export function bobik2ExpectedValues() {
  return [
    ...BOBIK2.sealed.map((s) => ({ ok: true, value: s.value })),
    ...BOBIK2.stc.map((s) => ({ ok: true, value: s.value })),
    ...BOBIK2.negative.map((n) => ({ ok: false, error: n.error })),
  ];
}

export function bobik2LeaseArgs(overrides = {}) {
  return {
    ...bobik2Interview(),
    study_code: "BOB-0001",
    kind: "addendum",
    session_seq: null,
    agent_run_id: null,
    lease_public_key_der: BOBIK2.rsa_lease_key.public_key_spki_der,
    ...overrides,
  };
}
