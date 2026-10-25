// Fabryka sejfu do testów rdzenia: atrapy authenticatora i UI, zegar i timery pod kontrolą testu.
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
