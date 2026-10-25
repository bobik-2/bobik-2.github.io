// WebAuthn z rozszerzeniem PRF. `credentials` = navigator.credentials
// (wstrzykiwane, żeby dało się testować bez przeglądarki).

import { toB64url } from "./b64.js";

export class WebAuthnError extends Error {
  constructor(code, cause) {
    super(code, { cause });
    this.code = code;
  }
}

function mapDomError(e) {
  if (e instanceof WebAuthnError) return e;
  if (e?.name === "NotAllowedError") return new WebAuthnError("not_allowed", e);
  if (e?.name === "InvalidStateError") return new WebAuthnError("already_registered", e);
  if (e?.name === "SecurityError") return new WebAuthnError("bad_rp_id", e);
  return new WebAuthnError("webauthn_failed", e);
}

const asBytes = (buf) => (buf ? new Uint8Array(buf) : null);
const descriptor = (id) => ({ type: "public-key", id });

// D5: tylko klucze sprzętowe. Passkeye platformowe (Touch ID / pęk kluczy
// iCloud, Windows Hello) i telefon przez QR (hybrid) synchronizują się
// albo żyją poza kontrolą kliniki — odrzucamy je.
const NOT_HARDWARE_TRANSPORTS = ["internal", "hybrid"];

function assertSecurityKey(cred, transports) {
  if (cred.authenticatorAttachment === "platform") throw new WebAuthnError("not_security_key");
  if (transports.some((t) => NOT_HARDWARE_TRANSPORTS.includes(t))) throw new WebAuthnError("not_security_key");
}

// AAGUID z attestedCredentialData (authenticatorData, offset 37). Zera =
// przeglądarka go ukryła (attestation "none") -> null.
function aaguidOf(authData) {
  const d = new Uint8Array(authData);
  if (d.length < 53 || !(d[32] & 0x40)) return null;
  const hex = Array.from(d.subarray(37, 53), (b) => b.toString(16).padStart(2, "0")).join("");
  if (/^0+$/.test(hex)) return null;
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Rejestracja klucza nierezydentnego. prfFirst bywa null: YubiKey bez
// hmac-secret-mc zwraca przy create() tylko `enabled` — wtedy wywołujący
// robi evaluatePrf (drugie dotknięcie).
export async function registerCredential(credentials, { rpId, rpName, userId, userName, displayName, salt, excludeIds = [] }) {
  let cred;
  try {
    cred = await credentials.create({
      publicKey: {
        rp: { id: rpId, name: rpName },
        user: { id: userId, name: userName, displayName },
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        excludeCredentials: excludeIds.map(descriptor),
        // Rozstrzygnięcie 6: PIN obowiązkowy. hmac-secret z UV i bez UV to różne sekrety, więc wybór
        // wiąże wszystkie wrapy F3 na zawsze; bez PIN-u znaleziony YubiKey + kopia wrapu wystarczają.
        authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "discouraged", userVerification: "required" },
        hints: ["security-key"],
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (e) {
    throw mapDomError(e);
  }
  const transports = cred.response.getTransports?.() ?? [];
  assertSecurityKey(cred, transports);
  const prf = cred.getClientExtensionResults().prf;
  if (!prf?.enabled) throw new WebAuthnError("no_prf");
  return {
    credentialId: new Uint8Array(cred.rawId),
    prfEnabled: true,
    prfFirst: asBytes(prf.results?.first),
    aaguid: cred.response.getAuthenticatorData ? aaguidOf(cred.response.getAuthenticatorData()) : null,
    transports,
  };
}

// Jedno get() dla wszystkich kluczy (evalByCredential, każdy z własną solą).
// Odpowiada włożony YubiKey; `index` wskazuje, który z `keys`.
export async function evaluatePrf(credentials, { rpId, keys }) {
  if (keys.length === 0) throw new WebAuthnError("no_keys");
  let assertion;
  try {
    assertion = await credentials.get({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId,
        allowCredentials: keys.map((k) => descriptor(k.credentialId)),
        userVerification: "required",
        hints: ["security-key"],
        extensions: {
          prf: { evalByCredential: Object.fromEntries(keys.map((k) => [toB64url(k.credentialId), { first: k.salt }])) },
        },
      },
    });
  } catch (e) {
    throw mapDomError(e);
  }
  assertSecurityKey(assertion, []);
  const rawId = toB64url(assertion.rawId);
  const index = keys.findIndex((k) => toB64url(k.credentialId) === rawId);
  if (index < 0) throw new WebAuthnError("unknown_credential");
  const first = assertion.getClientExtensionResults().prf?.results?.first;
  if (!first) throw new WebAuthnError("no_prf");
  return { index, prfFirst: new Uint8Array(first) };
}

// true/false wg getClientCapabilities(); null = przeglądarka nie mówi.
export async function prfSupport(win) {
  const PKC = win.PublicKeyCredential;
  if (!PKC) return false;
  if (typeof PKC.getClientCapabilities !== "function") return null;
  try {
    const caps = await PKC.getClientCapabilities();
    return caps["extension:prf"] === true;
  } catch {
    return null;
  }
}
