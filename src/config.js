// Konfiguracja sejfu zaszyta w kodzie. Zmiana = nowy release.

export const VERSION = "0.2.0";

// Origin sejfu: https://bobik-2.github.io (organizacja GitHub bobik-2),
// RP ID WebAuthn = "bobik-2.github.io" (w kodzie location.hostname).

// Originy panelu bobik-2, którym sejf odpowiada na postMessage (rozstrzygnięcie 11).
// TODO przed użyciem produkcyjnym (README, „Przed użyciem produkcyjnym"): dopisać hosty
// produkcyjne panelu — nowy release. Blok między znacznikami podmienia przy serwowaniu
// scripts/serve.mjs --dev-config (dev i E2E); build z tagów go nie zmienia.
export const ALLOWED_PARENT_ORIGINS = Object.freeze([
  // <parent-origins>
  "http://127.0.0.1:8000", // atrapa panelu w testach E2E (decyzja planu P12)
  // </parent-origins>
]);
