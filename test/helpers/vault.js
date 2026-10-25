// Fabryka sejfu do testów rdzenia: atrapy authenticatora i UI, zegar i timery pod kontrolą testu.
import { fromB64url } from "../../src/b64.js";
import { BOBIK2, loadSejf } from "./vectors.js";
import { VERSION } from "../../src/config.js";
import { createVault } from "../../src/core.js";
import { fakeAuthenticators } from "./fake-webauthn.js";
import { fakeUi } from "./fake-ui.js";

export function manualTimers() {
  const pending = new Map();
  let n = 0;
  return {
    pending,
    setTimeout(fn) {
      pending.set(++n, fn);
      return n;
    },
    clearTimeout(id) {
      pending.delete(id);
    },
    fireAll() {
      for (const [id, fn] of [...pending]) {
        pending.delete(id);
        fn();
      }
    },
  };
}

export function makeVault({ auth = fakeAuthenticators(), ui = fakeUi(), revoked = { revoked: [] }, ready, browserOk = true, prf = true, clock } = {}) {
  const events = [];
  const timers = manualTimers();
  const vault = createVault({
    version: VERSION,
    ready: ready ?? Promise.resolve(revoked),
    browserOk,
    prf: Promise.resolve(prf),
    credentials: auth.credentials,
    rpId: "localhost",
    ui,
    emit: (msg) => events.push(msg),
    now: clock ? () => clock.t : undefined,
    timers,
  });
  let seq = 0;
  const call = (op, args = {}) => vault.respond({ v: 1, id: `t${++seq}`, op, ...args });
  async function ok(op, args) {
    const res = await call(op, args);
    if (!res.ok) throw new Error(`${op}: ${res.error}`);
    return res.result;
  }
  return { vault, call, ok, auth, ui, events, timers };
}

// Rejestracja dwóch nowych kluczy: przed każdym „Zarejestruj klucz n" wkładany jest nowy YubiKey.
export async function registerDoctor(t, { doctor_id = 17, display_name = "dr Anna Nowak" } = {}) {
  const previous = t.ui.onAsk;
  t.ui.onAsk = (prompt) => {
    if (prompt.kind === "register_key") t.auth.insertNew();
  };
  try {
    return await t.ok("register", { doctor_id, display_name });
  } finally {
    t.ui.onAsk = previous;
  }
}

export async function unlockDoctor(t, reg, { doctor_id = 17, index = 1 } = {}) {
  t.auth.insert(reg.credentials[index].credential_id);
  return t.ok("unlock", { doctor_id, public_key_der: reg.public_key_der, credentials: reg.credentials });
}

// Odblokowanie lekarzem z sejf_v1.json: „klucze" atrapy zwracają prf_output z wektora.
export async function unlockFromVector(t) {
  const S = loadSejf();
  for (const c of S.credentials) t.auth.addFixed(fromB64url(c.credential_id), fromB64url(c.prf_output));
  t.auth.insert(S.credentials[0].credential_id);
  await t.ok("unlock", { doctor_id: S.doctor.doctor_id, public_key_der: S.doctor.public_key_spki_der, credentials: S.credentials });
  return S;
}

// Klucz kliniki z bobik2_v1.json, otwierany grantem F4 z sejf_v1.json.
export function loadBobik2Clinic(t, S) {
  return t.ok("load_clinic_key", {
    clinic_id: BOBIK2.clinic_id,
    clinic_key_id: BOBIK2.clinic_key_id,
    clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
    wrapped_private: S.clinic_grant.wrapped_private,
  });
}
