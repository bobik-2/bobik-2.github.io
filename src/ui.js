// UI sejfu: potwierdzenia, licznik, odcisk, ekrany blokady. Teksty od panelu (etykiety, study_code)
// są nieuwierzytelnione (B-R8) i trafiają do DOM wyłącznie przez textContent (Review Focus 2).
import { VaultError } from "./errors.js";
import { formatCounters, statusText } from "./prompts.js";

// Przegląd 9–10, M-1: operacje bez WebAuthn (klucz kliniki, grant, dzierżawa) chroni tylko kliknięcie
// w ramce, którą przejęty panel może przykryć przynętą. Przycisk zatwierdzenia jest nieaktywny przez
// chwilę po pokazaniu (kliknięcie „w locie” w niego nie trafi), a fokus stoi na „Anuluj”.
export const CONFIRM_DELAY_MS = 1000;

export function createUi(doc, { timers = globalThis } = {}) {
  const el = (id) => {
    const node = doc.getElementById(id);
    if (!node) throw new Error(`ui: brak #${id} w index.html`);
    return node;
  };
  const status = el("status");
  const fingerprint = el("fingerprint");
  const counter = el("counter");
  const prompt = el("prompt");
  const title = el("prompt-title");
  const lines = el("prompt-lines");
  const ok = el("prompt-ok");
  const cancel = el("prompt-cancel");
  const lock = el("lock");
  let pending = null;
  let armTimer = null;

  function disarm() {
    if (armTimer !== null) timers.clearTimeout(armTimer);
    armTimer = null;
  }
  function settle(finish) {
    if (!pending) return;
    const current = pending;
    pending = null;
    disarm();
    prompt.hidden = true;
    finish(current);
  }
  ok.addEventListener("click", () => {
    if (ok.disabled) return;
    settle((p) => p.resolve());
  });
  cancel.addEventListener("click", () => settle((p) => p.reject(new VaultError("user_rejected"))));

  return {
    ask(spec) {
      if (pending) return Promise.reject(new VaultError("busy"));
      title.textContent = spec.title;
      // `bound`: wiersz z wartością związaną kryptograficznie (odcisk, numer wywiadu) — wyróżniony.
      // `untrusted`: wiersz z etykietą od panelu — w jednej linii (CSS nowrap + ellipsis), więc po
      // zawinięciu nie udaje osobnego wiersza, np. odcisku (automatyczny przegląd bezpieczeństwa M-2).
      const bound = new Set(spec.bound ?? []);
      const untrusted = new Set(spec.untrusted ?? []);
      lines.replaceChildren(
        ...spec.lines.map((text, i) => {
          const p = doc.createElement("p");
          p.textContent = text;
          p.className = bound.has(i) ? "bound" : untrusted.has(i) ? "untrusted" : "";
          return p;
        }),
      );
      ok.textContent = spec.confirm;
      cancel.textContent = spec.cancel;
      prompt.hidden = false;
      disarm();
      ok.disabled = true;
      armTimer = timers.setTimeout(() => {
        armTimer = null;
        ok.disabled = false;
      }, CONFIRM_DELAY_MS);
      cancel.focus();
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
      });
    },
    cancel(code) {
      settle((p) => p.reject(new VaultError(code)));
    },
    render(view) {
      status.textContent = statusText(view);
      fingerprint.hidden = !view.fingerprint;
      fingerprint.textContent = view.fingerprint ? `Odcisk Twojego klucza: ${view.fingerprint}` : "";
      counter.hidden = !view.counters;
      counter.textContent = view.counters ? formatCounters(view.counters) : "";
      lock.hidden = view.state !== "unlocked";
      doc.body.dataset.state = view.state;
    },
    onLock(fn) {
      lock.addEventListener("click", fn);
    },
  };
}
