// Spięcie rdzenia sejfu z oknem przeglądarki: filtr rodzica, UI, zegar blokady.
import { browserOk } from "./browser.js";
import { ALLOWED_PARENT_ORIGINS } from "./config.js";
import { createVault } from "./core.js";
import { acceptMessage, isTopLevel } from "./parent.js";
import { fetchRevoked } from "./revocation.js";
import { createUi } from "./ui.js";
import { prfSupport } from "./webauthn.js";

const TICK_MS = 5_000;
const ui = createUi(document);

if (isTopLevel(window)) {
  // Rozstrzygnięcie 9: sejf otwarty jako strona najwyższego poziomu nie przyjmuje wiadomości.
  ui.render({ state: "refusing", refusal: "top_level", fingerprint: null, counters: null });
} else {
  let parentOrigin = null;
  const vault = createVault({
    ready: fetchRevoked(fetch, new URL("../revoked.json", import.meta.url)),
    browserOk: browserOk(window),
    prf: prfSupport(window),
    credentials: navigator.credentials,
    rpId: location.hostname,
    ui,
    emit: (msg) => {
      // Zdarzenia tylko do rodzica, który już przeszedł filtr — nigdy "*".
      if (parentOrigin) window.parent.postMessage(msg, parentOrigin);
    },
  });
  ui.onLock(() => vault.lock("user"));
  setInterval(() => vault.tick(), TICK_MS);
  window.addEventListener("message", async (event) => {
    if (!acceptMessage(event, window, ALLOWED_PARENT_ORIGINS)) return;
    parentOrigin = event.origin;
    const response = await vault.respond(event.data);
    event.source.postMessage(response, event.origin);
  });
}
