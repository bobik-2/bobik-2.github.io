// Kto może rozmawiać z sejfem (spec B, rozstrzygnięcie 9; decyzja planu P6).
// frame-ancestors nie działa w <meta>, a GitHub Pages nie daje nagłówków — stąd weryfikacja w JS.

export const isTopLevel = (win) => win.parent === win;

export function acceptMessage(event, win, allowedOrigins) {
  if (event.source !== win.parent) return false;
  if (!allowedOrigins.includes(event.origin)) return false;
  // location.ancestorOrigins (Chromium, WebKit, Firefox): [0] = origin rodzica, dalej kolejni przodkowie.
  // Sejf musi siedzieć bezpośrednio w dokumencie panelu najwyższego poziomu, więc lista ma dokładnie
  // jeden wpis. Obca strona osadzająca dozwolony panel daje zawsze dwa — także w Firefoksie, który
  // maskuje je do "null" (zmierzone: ["null","null"] z no-referrer, ["null", obcy] bez; przegląd 9–10
  // L-3 i automatyczny przegląd bezpieczeństwa). Jedyny wpis może być "null": Firefox maskuje tak
  // rodzica przy iframe'ie B2 z referrerpolicy="no-referrer"; rodzica uwierzytelniają wtedy
  // event.source i event.origin z listy. Chromium i WebKit nie maskują — wtedy [0] === event.origin.
  // Brak listy (starsze przeglądarki) — rozstrzyga event.origin.
  const ancestors = win.location.ancestorOrigins;
  if (!ancestors) return true;
  if (ancestors.length !== 1) return false;
  if (ancestors[0] !== "null" && ancestors[0] !== event.origin) return false;
  return true;
}
