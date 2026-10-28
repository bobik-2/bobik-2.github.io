// Konfiguracja sejfu zaszyta w kodzie. Zmiana = nowy release.

export const VERSION = "0.3.0";

// Origin sejfu: https://bobik-2.github.io (organizacja GitHub bobik-2),
// RP ID WebAuthn = "bobik-2.github.io" (w kodzie location.hostname).

// Originy panelu bobik-2, którym sejf odpowiada na postMessage (rozstrzygnięcie 11). Wyłącznie
// https://; nowy host panelu (np. domena kliniki) = nowy release. Blok między znacznikami podmienia
// przy serwowaniu scripts/serve.mjs --dev-config (dev i E2E); build z tagów go nie zmienia.
export const ALLOWED_PARENT_ORIGINS = Object.freeze([
  // <parent-origins>
  "https://bobik.iplweb.pl", // panel produkcyjny bobik-2
  // </parent-origins>
]);
