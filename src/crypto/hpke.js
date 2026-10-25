// HPKE (RFC 9180, tryb base, single-shot): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM,
// AAD puste, kontekst w `info` (handoff, sekcja 4). Wynik: enc (65 B) ‖ szyfrogram ‖ tag.
import {
  Aes256Gcm,
  CipherSuite,
  DecapError,
  DeserializeError,
  DhkemP256HkdfSha256,
  HkdfSha256,
  OpenError,
  ValidationError,
} from "../vendor/hpke-core-1.9.0/mod.js";
import { concat } from "../bytes.js";

export const ENC_LEN = 65;

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

export async function hpkeSeal(recipientPublicKey, info, plaintext) {
  const { ct, enc } = await suite.seal({ recipientPublicKey, info }, plaintext);
  return concat(new Uint8Array(enc), new Uint8Array(ct));
}

// `recipientPair` MUSI być parą {privateKey, publicKey}: z samym nieeksportowalnym kluczem
// prywatnym @hpke/common zgaduje znak y klucza publicznego i myli się dla ok. połowy kluczy (spike).
export async function hpkeOpen(recipientPair, info, blob) {
  const plaintext = await suite.open({ recipientKey: recipientPair, enc: blob.slice(0, ENC_LEN), info }, blob.slice(ENC_LEN));
  return new Uint8Array(plaintext);
}

// Wyjątki, którymi @hpke/core kończy nieudane otwarcie: zły klucz, kontekst, enc albo szyfrogram.
export function isHpkeFailure(e) {
  return e instanceof OpenError || e instanceof DecapError || e instanceof DeserializeError || e instanceof ValidationError;
}
