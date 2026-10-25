// Import kluczy P-256 (ECDH) — lekarza, kliniki, odbiorcy grantu.
import { VaultError } from "../errors.js";

const P256 = { name: "ECDH", namedCurve: "P-256" };

// Klucz publiczny jest eksportowalny: @hpke/core serializuje pkR do kem_context.
export async function importP256Public(spki) {
  try {
    return await crypto.subtle.importKey("spki", spki, P256, true, []);
  } catch (e) {
    // DataError: bajty nie są SPKI DER albo to inna krzywa/algorytm (RSA, P-384);
    // NotSupportedError: algorytm z SPKI nieobsługiwany przez przeglądarkę.
    if (e?.name === "DataError" || e?.name === "NotSupportedError") throw new VaultError("bad_key");
    throw e;
  }
}

// Para {privateKey (extractable: false), publicKey} do HPKE-open (spike). Zeruje `pkcs8`
// zaraz po imporcie, także przy błędzie (rozstrzygnięcie 14).
export async function importP256Pair(pkcs8, publicKey) {
  try {
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, P256, false, ["deriveBits"]);
    return { privateKey, publicKey };
  } catch (e) {
    // DataError/NotSupportedError: tekst jawny grantu nie jest PKCS8 klucza P-256.
    if (e?.name === "DataError" || e?.name === "NotSupportedError") throw new VaultError("unwrap_failed");
    throw e;
  } finally {
    pkcs8.fill(0);
  }
}
