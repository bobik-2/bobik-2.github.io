// Atrapa navigator.credentials z PRF dla testów rdzenia w Node. Modeluje fizyczne klucze:
//   insertNew()            — włożony nowy YubiKey: następne create() go rejestruje,
//   insert(id)             — włożony zarejestrowany klucz (rawId w base64url),
//   remove()               — nic nie jest włożone,
//   addFixed(rawId, prf)   — klucz z wektora sejf_v1.json: PRF zawsze zwraca `prf`.
// PRF = HMAC-SHA256(sekret klucza, sól), więc ta sama sól daje ten sam wynik (jak hmac-secret).
import { toB64url } from "../../src/b64.js";

const notAllowed = () => new DOMException("brak pasującego klucza", "NotAllowedError");
const buffer = (bytes) => bytes.slice().buffer;

async function hmac(secret, salt) {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, salt));
}

function credential(rawId, prf) {
  return {
    rawId: buffer(rawId),
    authenticatorAttachment: "cross-platform",
    response: { getTransports: () => ["usb"] },
    getClientExtensionResults: () => ({ prf }),
  };
}

export function fakeAuthenticators({ prfAtCreate = true } = {}) {
  const keys = new Map();
  let inserted = null;
  const calls = { create: [], get: [] };
  return {
    calls,
    insertNew() {
      inserted = { fresh: true };
    },
    insert(id) {
      if (!keys.has(id)) throw new Error(`atrapa: nieznany klucz ${id}`);
      inserted = { id };
    },
    remove() {
      inserted = null;
    },
    addFixed(rawId, prfOutput) {
      keys.set(toB64url(rawId), { rawId, fixed: prfOutput });
    },
    credentials: {
      async create({ publicKey }) {
        calls.create.push(publicKey);
        if (inserted?.id) {
          const excluded = publicKey.excludeCredentials.some((d) => toB64url(d.id) === inserted.id);
          throw excluded ? new DOMException("klucz już zarejestrowany", "InvalidStateError") : notAllowed();
        }
        if (!inserted?.fresh) throw notAllowed();
        const rawId = crypto.getRandomValues(new Uint8Array(16));
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const id = toB64url(rawId);
        keys.set(id, { rawId, secret });
        inserted = { id };
        const salt = publicKey.extensions.prf.eval.first;
        const prf = prfAtCreate ? { enabled: true, results: { first: buffer(await hmac(secret, salt)) } } : { enabled: true };
        return credential(rawId, prf);
      },
      async get({ publicKey }) {
        calls.get.push(publicKey);
        const id = inserted?.id;
        if (!id || !publicKey.allowCredentials.some((d) => toB64url(d.id) === id)) throw notAllowed();
        const key = keys.get(id);
        const salt = publicKey.extensions.prf.evalByCredential[id].first;
        return credential(key.rawId, { results: { first: buffer(key.fixed ?? (await hmac(key.secret, salt))) } });
      },
    },
  };
}
