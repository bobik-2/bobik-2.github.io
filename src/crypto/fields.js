// F5: DEK wywiadu (clinic_wrap) i pola Sealed / SealedToClinic — format A, bez zmian.
import { bytesToUuid, concat, utf8 } from "../bytes.js";
import { VaultError } from "../errors.js";
import { dekInfo, sealedContext, STC_INFO_PREFIX, stcContext } from "./context.js";
import { ENC_LEN, hpkeOpen, isHpkeFailure } from "./hpke.js";

export const SEALED_VERSION = 0x01;
export const STC_VERSION = 0x02;
export const HEADER_LEN = 17;
const NONCE_LEN = 12;
const TAG_LEN = 16;
export const DEK_LEN = 32;
export const CLINIC_WRAP_LEN = ENC_LEN + DEK_LEN + TAG_LEN;

// Zwraca DEK jako bajty (rozstrzygnięcie 14) — wywołujący woła importDek albo wrapDekForLease, które je zerują.
export async function openClinicWrap(clinicPair, interviewId, blob) {
  if (blob.length !== CLINIC_WRAP_LEN) throw new VaultError("bad_blob");
  try {
    return await hpkeOpen(clinicPair, utf8(dekInfo(interviewId)), blob);
  } catch (e) {
    // Inny klucz kliniki albo inny wywiad w `info` — HPKE nie otwiera.
    if (isHpkeFailure(e)) throw new VaultError("decrypt_failed");
    throw e;
  }
}

export async function importDek(raw) {
  try {
    if (raw.length !== DEK_LEN) throw new VaultError("decrypt_failed");
    return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  } finally {
    raw.fill(0);
  }
}

export function sealedKeyId(blob) {
  if (blob.length < HEADER_LEN + NONCE_LEN + TAG_LEN || blob[0] !== SEALED_VERSION) throw new VaultError("bad_blob");
  return bytesToUuid(blob.subarray(1, HEADER_LEN));
}

export async function openSealed(dekKey, { interviewId, interviewKeyId, field, blob }) {
  if (sealedKeyId(blob) !== interviewKeyId) throw new VaultError("key_mismatch");
  const header = blob.subarray(0, HEADER_LEN);
  const aad = concat(header, utf8(`|${sealedContext(interviewId, field)}`));
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.subarray(HEADER_LEN, HEADER_LEN + NONCE_LEN), additionalData: aad, tagLength: 128 },
      dekKey,
      blob.subarray(HEADER_LEN + NONCE_LEN),
    );
  } catch (e) {
    // OperationError = zły tag: inne pole, inny wywiad albo inny DEK.
    if (e?.name === "OperationError") throw new VaultError("decrypt_failed");
    throw e;
  }
  return parseValue(new Uint8Array(plaintext));
}

export function stcKeyId(blob) {
  if (blob.length < HEADER_LEN + ENC_LEN + TAG_LEN || blob[0] !== STC_VERSION) throw new VaultError("bad_blob");
  return bytesToUuid(blob.subarray(1, HEADER_LEN));
}

export async function openStc(clinicPair, { clinicId, field, blob }) {
  stcKeyId(blob);
  const header = blob.subarray(0, HEADER_LEN);
  const info = concat(utf8(STC_INFO_PREFIX), header, utf8(`|${stcContext(clinicId, field)}`));
  let plaintext;
  try {
    plaintext = await hpkeOpen(clinicPair, info, blob.subarray(HEADER_LEN));
  } catch (e) {
    // Inna klinika albo inne pole w `info`, inny klucz kliniki.
    if (isHpkeFailure(e)) throw new VaultError("decrypt_failed");
    throw e;
  }
  return parseValue(plaintext);
}

function parseValue(plaintext) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch (e) {
    // TypeError: niepoprawny UTF-8 (fatal); SyntaxError: nie JSON (decyzja planu P15).
    if (e instanceof TypeError || e instanceof SyntaxError) throw new VaultError("bad_blob");
    throw e;
  }
}
