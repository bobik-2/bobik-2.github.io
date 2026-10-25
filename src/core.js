// Rdzeń sejfu: koperta, stany (refusing / locked / unlocked), busy, limit, blokada.
// Wszystko, co zależy od przeglądarki (DOM, postMessage, navigator.credentials, zegar), jest
// wstrzykiwane przez vault.js — rdzeń testuje się w Node (Vitest).
import { VERSION } from "./config.js";
import { codeOf, VaultError } from "./errors.js";
import { createLimiter, LIMITS } from "./limits.js";
import { OPS } from "./ops/index.js";
import { errorResponse, okResponse, parseRequest, ProtocolError } from "./protocol.js";
import { isRevoked } from "./revocation.js";
import { createSession } from "./session.js";

export function createVault({ version = VERSION, ready, browserOk, prf, credentials, rpId, ui, emit, now = () => Date.now(), timers = globalThis }) {
  let state = "locked";
  let refusal = null;
  let busy = false;
  let epoch = 0;
  let session = createSession();
  const limiter = createLimiter(now);

  const view = () => ({
    state,
    refusal,
    fingerprint: session.doctor?.fingerprint ?? null,
    counters: state === "unlocked" ? limiter.snapshot() : null,
  });
  const render = () => ui.render(view());

  // Żądania czekają na listę unieważnień (V-4): odpowiedź `locked` przed jej pobraniem
  // pozwoliłaby unieważnionej wersji przyjąć `register` / `unlock`.
  const init = ready.then((doc) => {
    if (isRevoked(version, doc)) {
      state = "refusing";
      refusal = "revoked";
    } else if (!browserOk) {
      state = "refusing";
      refusal = "browser_blocked";
    }
    render();
  });

  function lock(reason) {
    if (state === "refusing") return;
    const wasUnlocked = state === "unlocked";
    epoch += 1;
    session = createSession();
    limiter.reset();
    state = "locked";
    ui.cancel("locked");
    render();
    if (wasUnlocked) emit({ v: 1, event: "locked", reason });
  }

  // Potwierdzenie w UI sejfu; bez odpowiedzi przez 120 s → user_rejected (P4).
  function ask(prompt) {
    const timer = timers.setTimeout(() => ui.cancel("user_rejected"), LIMITS.INTERACTION_TIMEOUT_MS);
    return ui.ask(prompt).finally(() => timers.clearTimeout(timer));
  }

  // Limit (rozstrzygnięcie 1) sprawdzany przed pierwszym odszyfrowaniem; limit_reached blokuje sejf.
  function charge(usage, { record = true } = {}) {
    const verdict = limiter.verdict(usage);
    if (verdict === "limit_reached") {
      lock("limit");
      throw new VaultError("limit_reached");
    }
    if (verdict === "rate_limited") throw new VaultError("rate_limited");
    if (record) limiter.record(usage);
  }

  const ctx = {
    version,
    rpId,
    credentials,
    browserOk,
    prf,
    get state() {
      return state;
    },
    get refusal() {
      return refusal;
    },
    get session() {
      return session;
    },
    ask,
    charge,
    lock,
    unlockWith(startEpoch, doctor) {
      if (epoch !== startEpoch) throw new VaultError("locked");
      epoch += 1; // operacje sprzed ponownego odblokowania nie oddadzą wyników starymi kluczami
      session = createSession();
      session.doctor = doctor;
      state = "unlocked";
      limiter.start();
      render();
    },
  };

  async function dispatch(req) {
    const op = Object.hasOwn(OPS, req.op) ? OPS[req.op] : null;
    if (!op) throw new ProtocolError("unknown_op");
    if (op.needs !== "none" && state === "refusing") throw new VaultError(refusal);
    if (op.needs === "unlocked" && state !== "unlocked") throw new VaultError("locked");
    const args = op.parse(req);
    if (op.interactive && busy) throw new VaultError("busy");
    if (op.interactive) busy = true;
    const start = epoch;
    try {
      if (op.needs === "unlocked") limiter.touch();
      const result = await op.run(ctx, args, start);
      // Blokada w trakcie operacji: wynik policzony kluczami poprzedniej sesji nie wraca (P3).
      if (op.needs === "unlocked" && epoch !== start) throw new VaultError("locked");
      return result;
    } finally {
      if (op.interactive) busy = false;
    }
  }

  async function respond(data) {
    let id = null;
    try {
      const req = parseRequest(data);
      id = req.id;
      await init;
      return okResponse(id, await dispatch(req));
    } catch (e) {
      return errorResponse(id, codeOf(e));
    } finally {
      render();
    }
  }

  function tick() {
    if (state !== "unlocked") return;
    const reason = limiter.expired();
    if (reason) lock(reason);
    else render();
  }

  function keys() {
    const out = [];
    if (session.doctor) out.push(session.doctor.pair.privateKey);
    for (const clinic of session.clinics.values()) out.push(clinic.pair.privateKey);
    for (const dek of session.deks.values()) out.push(dek.key);
    return out;
  }

  return { respond, tick, lock: (reason = "user") => lock(reason), view, keys };
}
