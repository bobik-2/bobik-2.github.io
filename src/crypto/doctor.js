// F1–F3: wynik PRF (YubiKey) → HKDF-SHA256 → KEK (AES-256-GCM) → wrap PKCS8 klucza lekarza (ECDH P-256).
import { concat, utf8 } from "../bytes.js";
import { VaultError } from "../errors.js";
import { doctorKekInfo } from "./context.js";

export const WRAP_VERSION = 0x01;
const IV_LEN = 12;
const MIN_LEN = 1 + IV_LEN + 16;
const P256 = { name: "ECDH", namedCurve: "P-256" };

// F2. Zeruje `prf` zaraz po imporcie do HKDF (rozstrzygnięcie 14).
export async function deriveKek(prf, doctorId, credential) {
  try {
    const ikm = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(doctorKekInfo(doctorId, credential)) },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"],
    );
  } finally {
    prf.fill(0);
  }
}

// Para eksportowalna wyłącznie na potrzeby wrapKey (spike: wrapKey wymaga klucza eksportowalnego).
export async function generateDoctorKey() {
  const pair = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  return { pair, spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)) };
}

// F3: [0x01][iv 12 B][AES-256-GCM(KEK, iv, PKCS8, AAD) ‖ tag 16 B].
export async function wrapDoctorKey(privateKey, kek, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = await crypto.subtle.wrapKey("pkcs8", privateKey, kek, { name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: 128 });
  return concat(Uint8Array.of(WRAP_VERSION), iv, new Uint8Array(ct));
}

export async function unwrapDoctorKey(blob, kek, aad, { extractable = false } = {}) {
  if (blob.length < MIN_LEN || blob[0] !== WRAP_VERSION) throw new VaultError("unwrap_failed");
  try {
    return await crypto.subtle.unwrapKey(
      "pkcs8",
      blob.subarray(1 + IV_LEN),
      kek,
      { name: "AES-GCM", iv: blob.subarray(1, 1 + IV_LEN), additionalData: utf8(aad), tagLength: 128 },
      P256,
      extractable,
      ["deriveBits"],
    );
  } catch (e) {
    // OperationError: zły tag — inny YubiKey/PRF, inny doctor_id/credential, podmieniony SPKI (B-D4).
    // DataError: tag się zgodził, ale tekst jawny nie jest PKCS8 klucza P-256.
    if (e?.name === "OperationError" || e?.name === "DataError") throw new VaultError("unwrap_failed");
    throw e;
  }
}
