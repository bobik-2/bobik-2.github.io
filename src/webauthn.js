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
        authenticatorSelection: { residentKey: "discouraged", userVerification: "discouraged" },
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (e) {
    throw mapDomError(e);
  }
  const prf = cred.getClientExtensionResults().prf;
  if (!prf?.enabled) throw new WebAuthnError("no_prf");
  return { credentialId: new Uint8Array(cred.rawId), prfEnabled: true, prfFirst: asBytes(prf.results?.first) };
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
        userVerification: "discouraged",
        extensions: {
          prf: { evalByCredential: Object.fromEntries(keys.map((k) => [toB64url(k.credentialId), { first: k.salt }])) },
        },
      },
    });
  } catch (e) {
    throw mapDomError(e);
  }
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
