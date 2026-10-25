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

const IV = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b";

// Przegląd 9–10, L-1: potwierdzenia pokazują identyfikatory związane kryptograficznie (kontekst grantu,
// info clinic_wrap), a etykiety od panelu są opisane jako niezweryfikowane.
it("nadanie dostępu: odcisk w pierwszym wierszu, potem numer lekarza (kontekst grantu) i etykieta z panelu", () => {
  const fp = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH";
  const p = PROMPTS.grantAccess("dr Piotr", fp, 18);
  expect(p.kind).toBe("grant_access");
  expect(p.lines[0]).toBe(`Odcisk klucza odbiorcy: ${fp}`);
  expect(p.lines[1]).toBe("Odbiorca: lekarz nr 18");
  expect(p.lines[2]).toBe("Nazwa odbiorcy z panelu (niezweryfikowana): dr Piotr");
  expect(p.confirm).toBe("Odcisk zgodny — nadaj dostęp");
});

it("wiersze związane kryptograficznie (`bound`) i etykiety z panelu (`untrusted`) są oznaczone", () => {
  // Ponowny przegląd, N-3: numery związane kryptograficznie w osobnym wierszu `bound` — ellipsis
  // wiersza `untrusted` przy wąskiej ramce nie może ich uciąć.
  expect(PROMPTS.grantAccess("dr P", "X", 18)).toMatchObject({ bound: [0, 1], untrusted: [2] });
  expect(PROMPTS.createClinic("K", 5)).toMatchObject({ bound: [0], untrusted: [1] });
  expect(PROMPTS.grantLease({ kind: "addendum", interviewId: IV, studyCode: "S", sessionSeq: null, agentRunId: null })).toMatchObject({ bound: [0], untrusted: [1] });
  expect(PROMPTS.registerKey(1, "dr A")).toMatchObject({ untrusted: [0] });
});

it("klucz kliniki: numer kliniki (kontekst grantu) i etykieta z panelu", () => {
  const p = PROMPTS.createClinic("Klinika Testowa", 5);
  expect(p.lines[0]).toBe("Klinika nr 5");
  expect(p.lines[1]).toBe("Nazwa kliniki z panelu (niezweryfikowana): Klinika Testowa");
});

it.each([
  [{ kind: "addendum", interviewId: IV, studyCode: "BOB-1", sessionSeq: null, agentRunId: null }, ["dopisek", "7 dni"]],
  [{ kind: "repair", interviewId: IV, studyCode: "BOB-2", sessionSeq: 2, agentRunId: null }, ["sesji 2", "1 h"]],
  [{ kind: "repair", interviewId: IV, studyCode: "BOB-3", sessionSeq: null, agentRunId: 9 }, ["przebiegu agenta 9", "1 h"]],
])("dzierżawa %j: wywiad (UUID z info clinic_wrap), kod z panelu, rodzaj i czas (rozstrzygnięcie 2)", (lease, texts) => {
  const { lines } = PROMPTS.grantLease(lease);
  expect(lines[0]).toBe(`Wywiad: ${IV}`);
  expect(lines[1]).toBe(`Kod wywiadu z panelu: ${lease.studyCode}`);
  const all = lines.join("\n");
  for (const t of texts) expect(all).toContain(t);
  expect(all).toContain("deklaruje panel"); // I-1: czasu nie egzekwuje sejf
});

it("każde potwierdzenie ma rodzaj, tytuł, linie i oba przyciski", () => {
  const all = [
    PROMPTS.registerKey(1, "dr A"),
    PROMPTS.registerKey(2, "dr A"),
    PROMPTS.secondTouch(1),
    PROMPTS.unlock(),
    PROMPTS.addExisting(),
    PROMPTS.addNew(),
    PROMPTS.createClinic("Klinika", 5),
    PROMPTS.grantAccess("dr B", "X", 18),
    PROMPTS.grantLease({ kind: "addendum", interviewId: IV, studyCode: "S", sessionSeq: null, agentRunId: null }),
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
