// Klucze jednej sesji odblokowania — wyłącznie w pamięci (rozstrzygnięcie 13). Blokada podmienia
// cały obiekt, więc operacja zaczęta przed blokadą pisze do porzuconej sesji (P3).
export function createSession() {
  return { doctor: null, clinics: new Map(), deks: new Map() };
}
