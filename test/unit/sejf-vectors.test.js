import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { sha256Hex } from "../../src/bytes.js";
import { generateClinicKey, openClinicGrant } from "../../src/crypto/clinic.js";
import { doctorWrapAad } from "../../src/crypto/context.js";
import { deriveKek, generateDoctorKey, unwrapDoctorKey } from "../../src/crypto/doctor.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { fingerprint } from "../../src/fingerprint.js";
import { BOBIK2, b, loadSejf } from "../helpers/vectors.js";

const S = loadSejf();
const clinicSpkiHex = () => sha256Hex(b(BOBIK2.clinic.public_key_spki_der));

async function doctorPair(i, { doctorId = S.doctor.doctor_id, credential = S.credentials[i].credential_id, spki = b(S.doctor.public_key_spki_der) } = {}) {
  const c = S.credentials[i];
  const kek = await deriveKek(b(c.prf_output), doctorId, credential);
  const privateKey = await unwrapDoctorKey(b(c.wrapped_private), kek, doctorWrapAad(doctorId, credential, await sha256Hex(spki)));
  return { privateKey, publicKey: await importP256Public(b(S.doctor.public_key_spki_der)) };
}

describe("sejf_v1.json (V-1, część sejfu)", () => {
  it("kształt = kontrakt B2 (zadanie 10, S-1) + pola testowe (P14)", () => {
    expect(Object.keys(S).sort()).toEqual(["clinic_fingerprint", "clinic_grant", "credentials", "doctor", "format", "note", "rsa_wrapped_dek"]);
    expect(S.format).toBe("sejf_v1");
    expect(Object.keys(S.doctor).sort()).toEqual(["doctor_id", "fingerprint", "public_key_spki_der"]);
    expect(S.credentials).toHaveLength(2);
    for (const c of S.credentials) {
      expect(Object.keys(c).sort()).toEqual(["credential_id", "prf_output", "prf_salt", "wrapped_private"]);
      expect(b(c.prf_salt)).toHaveLength(32);
      const wrap = b(c.wrapped_private);
      expect(wrap[0]).toBe(1);
      expect(wrap.length).toBeGreaterThanOrEqual(29);
      expect(wrap.length).toBeLessThanOrEqual(1024);
    }
    expect(Object.keys(S.clinic_grant).sort()).toEqual(["clinic_id", "doctor_id", "wrapped_private"]);
    expect(S.clinic_grant).toMatchObject({ clinic_id: BOBIK2.clinic_id, doctor_id: S.doctor.doctor_id });
    const grant = b(S.clinic_grant.wrapped_private);
    expect(grant[0]).toBe(1);
    expect(grant.length).toBeGreaterThanOrEqual(82);
    expect(b(S.rsa_wrapped_dek)).toHaveLength(384);
  });

  it("F7: odcisk lekarza i odcisk kliniki (= bobik-2)", async () => {
    expect(await fingerprint(b(S.doctor.public_key_spki_der))).toBe(S.doctor.fingerprint);
    expect(S.clinic_fingerprint).toBe(BOBIK2.clinic.fingerprint);
  });

  it.each([0, 1])("F1–F4: poświadczenie %i odpakowuje klucz lekarza, a ten otwiera grant kliniki z bobik2_v1.json", async (i) => {
    const pair = await doctorPair(i);
    const pkcs8 = await openClinicGrant(pair, {
      clinicId: BOBIK2.clinic_id,
      doctorId: S.doctor.doctor_id,
      clinicSpkiHex: await clinicSpkiHex(),
      blob: b(S.clinic_grant.wrapped_private),
    });
    expect(toB64url(pkcs8)).toBe(BOBIK2.clinic.private_key_pkcs8_der);
  });

  it("F6: rsa_wrapped_dek otwiera klucz dzierżawy z bobik2_v1.json", async () => {
    const priv = await crypto.subtle.importKey("pkcs8", b(BOBIK2.rsa_lease_key.private_key_pkcs8_der), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
    expect(toB64url(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b(S.rsa_wrapped_dek))))).toBe(BOBIK2.dek);
  });
});

describe("sejf_v1.json — przypadki negatywne -> unwrap_failed", () => {
  it("zły doctor_id", async () => {
    await expect(doctorPair(0, { doctorId: S.doctor.doctor_id + 1 })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("zły credential (wrap poświadczenia 0 z identyfikatorem poświadczenia 1)", async () => {
    await expect(doctorPair(0, { credential: S.credentials[1].credential_id })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("podmieniony SPKI lekarza w F3", async () => {
    await expect(doctorPair(0, { spki: (await generateDoctorKey()).spki })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("podmieniony SPKI kliniki w F4", async () => {
    const pair = await doctorPair(0);
    const other = await sha256Hex((await generateClinicKey()).spki);
    const args = { clinicId: BOBIK2.clinic_id, doctorId: S.doctor.doctor_id, clinicSpkiHex: other, blob: b(S.clinic_grant.wrapped_private) };
    await expect(openClinicGrant(pair, args)).rejects.toMatchObject({ code: "unwrap_failed" });
  });
});
