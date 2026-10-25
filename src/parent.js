// Kto może rozmawiać z sejfem (spec B, rozstrzygnięcie 9; decyzja planu P6).
// frame-ancestors nie działa w <meta>, a GitHub Pages nie daje nagłówków — stąd weryfikacja w JS.

export const isTopLevel = (win) => win.parent === win;

export function acceptMessage(event, win, allowedOrigins) {
  if (event.source !== win.parent) return false;
  if (!allowedOrigins.includes(event.origin)) return false;
  // Chromium: ancestorOrigins[0] = origin rodzica, dalej kolejni przodkowie (Firefox: brak listy —
  // rozstrzyga event.origin). Każdy przodek musi być z listy: dozwolony panel w obcej stronie nie
  // przejdzie (L-3). Fail-closed dla "null": to przodek o nieznanym originie, np. obca strona, która
  // osadza panel z referrerpolicy="no-referrer". Zad. 9 zmierzyło, że iframe B2 (no-referrer) NIE
  // maskuje rodzica w Chromium (["http://127.0.0.1:8000"]), więc pierwotne założenie P6 o maskowaniu
  // jest nieaktualne. ancestorOrigins to DOMStringList, nie tablica — pętla po indeksach.
  const ancestors = win.location.ancestorOrigins;
  if (!ancestors) return true;
  for (let i = 0; i < ancestors.length; i++) {
    const origin = ancestors[i];
    if (origin === "null") return false;
    if (i === 0 && origin !== event.origin) return false;
    if (!allowedOrigins.includes(origin)) return false;
  }
  return true;
}
