import { expect, it } from "vitest";
import { formatCounters, PROMPTS, statusText } from "../../src/prompts.js";

it("licznik jak w specu (rozstrzygnięcie 1)", () => {
  expect(formatCounters({ interviews: 12, stc: 40, idleLeftMs: 13 * 60_000 + 1 })).toBe("Wywiady: 12/50 · wartości kliniki: 40/500 · blokada za 14 min");
});

it("statusy po polsku", () => {
  expect(statusText({ state: "locked" })).toBe("Sejf zablokowany");
  expect(statusText({ state: "unlocked" })).toBe("Sejf odblokowany");
  expect(statusText({ state: "refusing", refusal: "revoked" })).toContain("unieważniona");
  expect(statusText({ state: "refusing", refusal: "browser_blocked" })).toContain("Safari");
  expect(statusText({ state: "refusing", refusal: "top_level" })).toBe("Sejf działa wyłącznie osadzony w panelu bobik-2.");
});

it("nadanie dostępu: etykieta i odcisk odbiorcy, przycisk potwierdzenia odcisku", () => {
  const fp = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH";
  const p = PROMPTS.grantAccess("dr Piotr", fp);
  expect(p.kind).toBe("grant_access");
  expect(p.lines.join("\n")).toContain("dr Piotr");
  expect(p.lines.join("\n")).toContain(fp);
  expect(p.confirm).toBe("Odcisk zgodny — nadaj dostęp");
});

it.each([
  [{ kind: "addendum", studyCode: "BOB-1", sessionSeq: null, agentRunId: null }, ["BOB-1", "dopisek", "7 dni"]],
  [{ kind: "repair", studyCode: "BOB-2", sessionSeq: 2, agentRunId: null }, ["BOB-2", "sesji 2", "1 h"]],
  [{ kind: "repair", studyCode: "BOB-3", sessionSeq: null, agentRunId: 9 }, ["BOB-3", "przebiegu agenta 9", "1 h"]],
])("dzierżawa %j: wywiad, rodzaj i czas (rozstrzygnięcie 2)", (lease, texts) => {
  const all = PROMPTS.grantLease(lease).lines.join("\n");
  for (const t of texts) expect(all).toContain(t);
});

it("każde potwierdzenie ma rodzaj, tytuł, linie i oba przyciski", () => {
  const all = [
    PROMPTS.registerKey(1, "dr A"),
    PROMPTS.registerKey(2, "dr A"),
    PROMPTS.secondTouch(1),
    PROMPTS.unlock(),
    PROMPTS.addExisting(),
    PROMPTS.addNew(),
    PROMPTS.createClinic("Klinika"),
    PROMPTS.grantAccess("dr B", "X"),
    PROMPTS.grantLease({ kind: "addendum", studyCode: "S", sessionSeq: null, agentRunId: null }),
  ];
  for (const p of all) {
    expect(typeof p.kind).toBe("string");
    expect(p.title.length).toBeGreaterThan(0);
    expect(p.lines.length).toBeGreaterThan(0);
    expect(p.confirm.length).toBeGreaterThan(0);
    expect(p.cancel.length).toBeGreaterThan(0);
  }
  expect(all.map((p) => p.confirm)).toEqual([
    "Zarejestruj klucz 1",
    "Zarejestruj klucz 2",
    "Dotknij ponownie",
    "Odblokuj",
    "Potwierdź istniejącym kluczem",
    "Zarejestruj nowy klucz",
    "Załóż klucz",
    "Odcisk zgodny — nadaj dostęp",
    "Zatwierdź",
  ]);
});
