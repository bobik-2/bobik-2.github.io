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
import { WebAuthnError } from "./webauthn.js";

export function createVault({ version = VERSION, ready, browserOk, prf, credentials, rpId, ui, emit, now = () => Date.now(), timers = globalThis }) {
  let state = "locked";
  let refusal = null;
  let busy = false;
  // AbortController bieżącej operacji interaktywnej (busy = najwyżej jedna); lock() przerywa nim
  // natywne okno WebAuthn, żeby nie trzymało busy do zamknięcia przez przeglądarkę (L2).
  let controller = null;
  let epoch = 0;
  let session = createSession();
  const limiter = createLimiter(now);

  const view = () => ({
    state,
    refusal,
    // Numer lekarza związany przez AAD wrapu (odblokowanie się udało) — odbiorca grantu podaje go
    // nadającemu razem z odciskiem (końcowy przegląd, M-5).
    doctorId: session.doctor?.doctorId ?? null,
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
    controller?.abort();
    ui.cancel("locked");
    render();
    if (wasUnlocked) emit({ v: 1, event: "locked", reason });
  }

  // Potwierdzenie w UI sejfu; bez odpowiedzi przez 120 s → user_rejected (P4).
  function ask(prompt) {
    // Po blokadzie przerwana operacja nie pokazuje już kolejnych pytań (np. „Zarejestruj klucz 2").
    if (controller?.signal.aborted) return Promise.reject(new VaultError("locked"));
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
    get signal() {
      return controller?.signal;
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
    // Progi idle / max_age także na ścieżce żądania, nie tylko w tick(): timer w karcie w tle
    // bywa dławiony, a touch() poniżej odsunąłby termin bezczynności (przegląd 5–8, M1).
    if (op.needs === "unlocked") {
      const reason = limiter.expired();
      if (reason) {
        lock(reason);
        throw new VaultError("locked");
      }
    }
    const args = op.parse(req);
    if (op.interactive && busy) throw new VaultError("busy");
    if (op.interactive) {
      busy = true;
      controller = new AbortController();
    }
    const start = epoch;
    // Kontrola epoki po operacji: wszystkie wymagające odblokowania oraz jawnie oznaczone
    // (register, L3). Nie unlock: ten sam podbija epokę w unlockWith i tam ją sprawdza.
    const bound = op.needs === "unlocked" || op.bindsEpoch === true;
    try {
      if (op.needs === "unlocked") limiter.touch();
      const result = await op.run(ctx, args, start);
      // Blokada w trakcie operacji: wynik sprzed blokady nie wraca (P3).
      if (bound && epoch !== start) throw new VaultError("locked");
      // Termin minął w trakcie potwierdzenia (do 120 s, tick bywa dławiony): wynik operacji
      // interaktywnej nie wraca po idle / max_age (ponowny przegląd, N-1).
      if (op.interactive && op.needs === "unlocked") {
        const reason = limiter.expired();
        if (reason) {
          lock(reason);
          throw new VaultError("locked");
        }
      }
      return result;
    } catch (e) {
      // WebAuthnError po przerwaniu sygnałem (AbortError -> webauthn_failed) to skutek blokady,
      // nie błąd klucza: panel dostaje locked (P3). Inne błędy i AbortError bez blokady — bez zmian.
      if (e instanceof WebAuthnError && op.interactive && controller.signal.aborted) throw new VaultError("locked");
      throw e;
    } finally {
      if (op.interactive) {
        busy = false;
        controller = null;
      }
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
