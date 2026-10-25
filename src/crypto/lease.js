// F6: DEK dla dzierżawy = RSA-OAEP(SHA-256, MGF1-SHA-256, etykieta pusta) pod kluczem KMS
// RSA_DECRYPT_OAEP_3072_SHA256. WebCrypto RSA-OAEP z hash SHA-256 używa MGF1 z tym samym skrótem.
// Pochodzenia klucza sejf nie weryfikuje — ryzyko przyjęte (rozstrzygnięcie 2, B-R1).
import { VaultError } from "../errors.js";

export const LEASE_MODULUS_BITS = 3072;
export const RSA_WRAPPED_DEK_LEN = 384;
const RSA_OAEP = { name: "RSA-OAEP", hash: "SHA-256" };

export async function importLeaseKey(spki) {
  let key;
  try {
    key = await crypto.subtle.importKey("spki", spki, RSA_OAEP, false, ["encrypt"]);
  } catch (e) {
    // DataError: bajty nie są SPKI klucza RSA; NotSupportedError: algorytm nieobsługiwany.
    if (e?.name === "DataError" || e?.name === "NotSupportedError") throw new VaultError("bad_lease_key");
    throw e;
  }
  const { modulusLength, publicExponent } = key.algorithm;
  if (modulusLength !== LEASE_MODULUS_BITS || exponent(publicExponent) !== 65537) throw new VaultError("bad_lease_key");
  return key;
}

const exponent = (bytes) => bytes.reduce((n, byte) => n * 256 + byte, 0);

export async function wrapDekForLease(leaseKey, dek) {
  try {
    return new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, leaseKey, dek));
  } finally {
    dek.fill(0);
  }
}
