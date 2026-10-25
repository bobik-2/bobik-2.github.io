// Generuje test/vectors/sejf_v1.json (F1–F4, F6, F7 sejfu) z podstawionym wynikiem PRF i odświeża
// test/vectors/SHA256SUMS. Uruchamiać WYŁĄCZNIE przy zmianie formatu: ECDH/HPKE/RSA-OAEP są losowe,
// więc każdy przebieg daje inne bajty, a kopia pliku żyje też w bobik-2 (spec B, „Wektory krzyżowe").
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fromB64url, toB64url } from "../src/b64.js";
import { random, sha256Hex } from "../src/bytes.js";
import { sealClinicGrant } from "../src/crypto/clinic.js";
import { doctorWrapAad } from "../src/crypto/context.js";
import { deriveKek, generateDoctorKey, wrapDoctorKey } from "../src/crypto/doctor.js";
import { importLeaseKey, wrapDekForLease } from "../src/crypto/lease.js";
import { fingerprint } from "../src/fingerprint.js";

const DIR = "test/vectors";
const DOCTOR_ID = 17;
const b2 = JSON.parse(readFileSync(`${DIR}/bobik2_v1.json`, "utf8"));

const { pair, spki } = await generateDoctorKey();
const spkiHex = await sha256Hex(spki);
const credentials = [];
for (const idLen of [16, 32]) {
  const credentialId = random(idLen);
  const prfSalt = random(32);
  const prfOutput = random(32);
  const credential = toB64url(credentialId);
  const kek = await deriveKek(prfOutput.slice(), DOCTOR_ID, credential);
  const wrapped = await wrapDoctorKey(pair.privateKey, kek, doctorWrapAad(DOCTOR_ID, credential, spkiHex));
  credentials.push({
    credential_id: credential,
    prf_salt: toB64url(prfSalt),
    wrapped_private: toB64url(wrapped),
    prf_output: toB64url(prfOutput),
  });
}

const clinicSpki = fromB64url(b2.clinic.public_key_spki_der);
const grant = await sealClinicGrant(pair.publicKey, {
  clinicId: b2.clinic_id,
  doctorId: DOCTOR_ID,
  clinicSpkiHex: await sha256Hex(clinicSpki),
  pkcs8: fromB64url(b2.clinic.private_key_pkcs8_der),
});
const leaseKey = await importLeaseKey(fromB64url(b2.rsa_lease_key.public_key_spki_der));
const rsaWrapped = await wrapDekForLease(leaseKey, fromB64url(b2.dek));

const out = {
  format: "sejf_v1",
  note:
    "Wektory formatów sejfu dla bobik-2 (spec B, „Wektory krzyżowe”). Klucze wyłącznie testowe. Bajty: base64url bez paddingu (F8). " +
    "credentials: F1/F3 — wrap klucza lekarza pod KEK z HKDF(prf_output); prf_output to podstawiony wynik PRF (tylko do testów sejfu). " +
    "clinic_grant: F4 klucza kliniki z bobik2_v1.json dla klucza lekarza z tego pliku. rsa_wrapped_dek: F6 DEK-u z bobik2_v1.json " +
    "pod rsa_lease_key z bobik2_v1.json. clinic_fingerprint: F7 SPKI kliniki z bobik2_v1.json policzone w sejfie.",
  doctor: { doctor_id: DOCTOR_ID, public_key_spki_der: toB64url(spki), fingerprint: await fingerprint(spki) },
  credentials,
  clinic_grant: { clinic_id: b2.clinic_id, doctor_id: DOCTOR_ID, wrapped_private: toB64url(grant) },
  rsa_wrapped_dek: toB64url(rsaWrapped),
  clinic_fingerprint: await fingerprint(clinicSpki),
};
writeFileSync(`${DIR}/sejf_v1.json`, `${JSON.stringify(out, null, 2)}\n`);

const sums = ["bobik2_v1.json", "sejf_v1.json"].map(
  (name) => `${createHash("sha256").update(readFileSync(`${DIR}/${name}`)).digest("hex")}  ${name}`,
);
writeFileSync(`${DIR}/SHA256SUMS`, `${sums.join("\n")}\n`);
console.log(sums.join("\n"));
