// Konfiguracja sejfu zaszyta w kodzie. Zmiana = nowy release.

export const VERSION = "0.1.0";

// Origin sejfu: https://bobik-2.github.io (organizacja GitHub bobik-2),
// RP ID WebAuthn = "bobik-2.github.io".

// Originy panelu bobik-2, którym sejf odpowiada na postMessage.
// OTWARTE: domeny produkcyjne bobik-2 — dopisać przed pierwszym releasem.
export const ALLOWED_PARENT_ORIGINS = Object.freeze([
  "http://127.0.0.1:8000", // atrapa panelu w testach E2E
]);
