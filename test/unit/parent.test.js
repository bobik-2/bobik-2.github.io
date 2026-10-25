import { describe, expect, it } from "vitest";
import { acceptMessage, isTopLevel } from "../../src/parent.js";

const PANEL = "http://127.0.0.1:8000";
const DEV = "http://localhost:8000";

// location.ancestorOrigins to DOMStringList (length, [i], item(i)), nie tablica — bez .every/.map.
function stringList(values) {
  const list = { length: values.length, item: (i) => values[i] ?? null };
  values.forEach((v, i) => {
    list[i] = v;
  });
  return list;
}

function win({ ancestors } = {}) {
  const w = { parent: {}, location: {} };
  if (ancestors) w.location.ancestorOrigins = stringList(ancestors);
  return w;
}

describe("filtr rodzica (rozstrzygnięcie 9, P6, V-3, Review Focus 4)", () => {
  it("rodzic z listy -> przyjęte", () => {
    const w = win();
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(true);
  });

  it.each([
    ["obcy origin", (w) => ({ source: w.parent, origin: "https://evil.example" })],
    ['origin "null" (sandbox, data:)', (w) => ({ source: w.parent, origin: "null" })],
    ["źródło inne niż rodzic (popup, inna ramka)", () => ({ source: {}, origin: PANEL })],
  ])("%s -> odrzucone", (_name, makeEvent) => {
    const w = win();
    expect(acceptMessage(makeEvent(w), w, [PANEL])).toBe(false);
  });

  it("ancestorOrigins[0] inny niż event.origin -> odrzucone (Chromium)", () => {
    const w = win({ ancestors: [DEV] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL, DEV])).toBe(false);
  });

  it("ancestorOrigins[0] === event.origin -> przyjęte", () => {
    const w = win({ ancestors: [PANEL] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(true);
  });

  it('ancestorOrigins zamaskowane ("null", referrerpolicy=no-referrer) -> rozstrzyga event.origin', () => {
    const w = win({ ancestors: ["null"] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(true);
    expect(acceptMessage({ source: w.parent, origin: "https://evil.example" }, w, [PANEL])).toBe(false);
  });

  // Przegląd 9–10, L-3: dozwolony panel osadzony w obcej stronie ([1] obcy) nie przechodzi.
  it("dalszy przodek spoza listy -> odrzucone (Chromium)", () => {
    const w = win({ ancestors: [PANEL, "https://evil.example"] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(false);
  });

  it("wszyscy przodkowie z listy -> przyjęte; zamaskowany \"null\" w dalszym przodku pomijany", () => {
    const w = win({ ancestors: [PANEL, DEV] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL, DEV])).toBe(true);
    const masked = win({ ancestors: [PANEL, "null"] });
    expect(acceptMessage({ source: masked.parent, origin: PANEL }, masked, [PANEL])).toBe(true);
  });

  it("zamaskowany rodzic, obcy dalszy przodek -> odrzucone", () => {
    const w = win({ ancestors: ["null", "https://evil.example"] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(false);
  });

  it("isTopLevel: window.parent === window", () => {
    const top = {};
    top.parent = top;
    expect(isTopLevel(top)).toBe(true);
    expect(isTopLevel(win())).toBe(false);
  });
});
