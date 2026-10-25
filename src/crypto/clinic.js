// F4: grant klucza prywatnego kliniki = [0x01] ‖ HPKE(PKCS8 kliniki) do klucza publicznego lekarza.
import { concat, utf8 } from "../bytes.js";
import { VaultError } from "../errors.js";
import { clinicGrantInfo } from "./context.js";
import { ENC_LEN, hpkeOpen, hpkeSeal, isHpkeFailure } from "./hpke.js";

export const GRANT_VERSION = 0x01;
const MIN_LEN = 1 + ENC_LEN + 16;
const P256 = { name: "ECDH", namedCurve: "P-256" };

// Para eksportowalna tylko po to, by wyjąć SPKI i PKCS8 do pierwszego grantu (create_clinic_key).
// Wywołujący zeruje `pkcs8` zaraz po sealClinicGrant; para wychodzi z zasięgu.
export async function generateClinicKey() {
  const pair = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  return {
    spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
    pkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

export async function sealClinicGrant(recipientPublicKey, { clinicId, doctorId, clinicSpkiHex, pkcs8 }) {
  const sealed = await hpkeSeal(recipientPublicKey, utf8(clinicGrantInfo(clinicId, doctorId, clinicSpkiHex)), pkcs8);
  return concat(Uint8Array.of(GRANT_VERSION), sealed);
}

// Zwraca PKCS8 kliniki jako bajty (rozstrzygnięcie 14): wywołujący importuje je (importP256Pair) albo zeruje.
export async function openClinicGrant(doctorPair, { clinicId, doctorId, clinicSpkiHex, blob }) {
  if (blob.length < MIN_LEN || blob[0] !== GRANT_VERSION) throw new VaultError("unwrap_failed");
  try {
    return await hpkeOpen(doctorPair, utf8(clinicGrantInfo(clinicId, doctorId, clinicSpkiHex)), blob.subarray(1));
  } catch (e) {
    // Grant dla innego lekarza, innej kliniki albo z podmienionym SPKI kliniki — HPKE nie otwiera.
    if (isHpkeFailure(e)) throw new VaultError("unwrap_failed");
    throw e;
  }
}
