// Kto może rozmawiać z sejfem (spec B, rozstrzygnięcie 9; decyzja planu P6).
// frame-ancestors nie działa w <meta>, a GitHub Pages nie daje nagłówków — stąd weryfikacja w JS.

export const isTopLevel = (win) => win.parent === win;

export function acceptMessage(event, win, allowedOrigins) {
  if (event.source !== win.parent) return false;
  if (!allowedOrigins.includes(event.origin)) return false;
  // Chromium: ancestorOrigins[0] = origin rodzica. "null" = zamaskowany przez referrerpolicy
  // iframe'a (B2 osadza z no-referrer) — wtedy, jak w Firefoksie, rozstrzyga event.origin.
  const ancestors = win.location.ancestorOrigins;
  if (ancestors && ancestors.length > 0 && ancestors[0] !== "null" && ancestors[0] !== event.origin) return false;
  return true;
}
