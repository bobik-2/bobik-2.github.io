// Konfiguracja sejfu zaszyta w kodzie. Zmiana = nowy release.

export const VERSION = "0.1.0";

// Originy panelu bobik-2, którym sejf odpowiada na postMessage.
// OTWARTE: domeny produkcyjne bobik-2 — dopisać przed pierwszym releasem.
export const ALLOWED_PARENT_ORIGINS = Object.freeze([
  "http://127.0.0.1:8000", // atrapa panelu w testach E2E
]);
