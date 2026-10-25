// Atrapa UI sejfu. Odpowiedzi kolejno z `answers`: "ok" (domyślnie), "cancel" (Anuluj),
// "hang" (lekarz nie klika — do testów blokady i limitu czasu). `onAsk(prompt, index)` pozwala
// testowi „włożyć" klucz przed wywołaniem WebAuthn, które następuje zaraz po kliknięciu.
import { VaultError } from "../../src/errors.js";

export function fakeUi({ answers = [] } = {}) {
  let hung = null;
  const ui = {
    answers,
    prompts: [],
    views: [],
    onAsk: null,
    get hanging() {
      return hung !== null;
    },
    ask(prompt) {
      ui.prompts.push(prompt);
      ui.onAsk?.(prompt, ui.prompts.length - 1);
      const answer = answers.shift() ?? "ok"; // shift: answers.push() w trakcie testu też działa
      if (answer === "cancel") return Promise.reject(new VaultError("user_rejected"));
      if (answer === "hang") return new Promise((_resolve, reject) => { hung = reject; });
      return Promise.resolve();
    },
    cancel(code) {
      if (!hung) return;
      const reject = hung;
      hung = null;
      reject(new VaultError(code));
    },
    render(view) {
      ui.views.push(view);
    },
  };
  return ui;
}
