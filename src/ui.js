// UI sejfu: potwierdzenia, licznik, odcisk, ekrany blokady. Teksty od panelu (etykiety, study_code)
// są nieuwierzytelnione (B-R8) i trafiają do DOM wyłącznie przez textContent (Review Focus 2).
import { VaultError } from "./errors.js";
import { formatCounters, statusText } from "./prompts.js";

export function createUi(doc) {
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

  function settle(finish) {
    if (!pending) return;
    const current = pending;
    pending = null;
    prompt.hidden = true;
    finish(current);
  }
  ok.addEventListener("click", () => settle((p) => p.resolve()));
  cancel.addEventListener("click", () => settle((p) => p.reject(new VaultError("user_rejected"))));

  return {
    ask(spec) {
      if (pending) return Promise.reject(new VaultError("busy"));
      title.textContent = spec.title;
      lines.replaceChildren(
        ...spec.lines.map((text) => {
          const p = doc.createElement("p");
          p.textContent = text;
          return p;
        }),
      );
      ok.textContent = spec.confirm;
      cancel.textContent = spec.cancel;
      prompt.hidden = false;
      ok.focus();
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
