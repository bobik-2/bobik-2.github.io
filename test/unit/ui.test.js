// UI potwierdzeń na minimalnej atrapie DOM (bez jsdom): fokus i opóźnienie przycisku zatwierdzenia.
import { describe, expect, it } from "vitest";
import { CONFIRM_DELAY_MS, createUi } from "../../src/ui.js";
import { manualTimers } from "../helpers/vault.js";

const IDS = ["status", "fingerprint", "counter", "prompt", "prompt-title", "prompt-lines", "prompt-ok", "prompt-cancel", "lock"];

function fakeDoc() {
  const doc = { activeElement: null, body: { dataset: {} } };
  const element = (id) => {
    const listeners = {};
    const node = {
      id,
      hidden: false,
      disabled: false,
      textContent: "",
      className: "",
      children: [],
      addEventListener(type, fn) {
        (listeners[type] ??= []).push(fn);
      },
      // Jak w przeglądarce: kliknięcie wyłączonego przycisku nie wywołuje handlera.
      click() {
        if (node.disabled) return;
        for (const fn of listeners.click ?? []) fn();
      },
      // Bez strażnika `disabled` — sprawdza, że handler sam odrzuca kliknięcie wyłączonego przycisku.
      dispatchClick() {
        for (const fn of listeners.click ?? []) fn();
      },
      focus() {
        doc.activeElement = node;
      },
      replaceChildren(...kids) {
        node.children = kids;
      },
    };
    return node;
  };
  const nodes = Object.fromEntries(IDS.map((id) => [id, element(id)]));
  doc.getElementById = (id) => nodes[id] ?? null;
  doc.createElement = () => element(null);
  return { doc, nodes };
}

const SPEC = { title: "T", lines: ["a"], confirm: "Zatwierdź", cancel: "Anuluj" };

function setup() {
  const { doc, nodes } = fakeDoc();
  const timers = manualTimers();
  const ui = createUi(doc, { timers });
  return { doc, nodes, timers, ui, ok: nodes["prompt-ok"], cancel: nodes["prompt-cancel"] };
}

describe("potwierdzenia w sejfie (przegląd 9–10, M-1: clickjacking)", () => {
  it("fokus na „Anuluj”, nie na „Zatwierdź” (Enter/Spacja nie zatwierdza)", () => {
    const t = setup();
    t.ui.ask(SPEC);
    expect(t.doc.activeElement).toBe(t.cancel);
  });

  it(`„Zatwierdź” nieaktywny przez ${CONFIRM_DELAY_MS} ms po pokazaniu; kliknięcie w tym czasie nic nie robi`, async () => {
    const t = setup();
    let settled = false;
    const answer = t.ui.ask(SPEC).then(() => {
      settled = true;
    });
    expect(CONFIRM_DELAY_MS).toBe(1000);
    expect(t.ok.disabled).toBe(true);
    t.ok.dispatchClick();
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(t.nodes.prompt.hidden).toBe(false);
    t.timers.fireAll();
    expect(t.ok.disabled).toBe(false);
    t.ok.click();
    await answer;
    expect(settled).toBe(true);
    expect(t.nodes.prompt.hidden).toBe(true);
  });

  it("„Anuluj” działa od razu", async () => {
    const t = setup();
    const answer = t.ui.ask(SPEC);
    t.cancel.click();
    await expect(answer).rejects.toMatchObject({ code: "user_rejected" });
  });

  it("timer poprzedniego pytania nie odblokowuje przycisku następnego", () => {
    const t = setup();
    t.ui.ask(SPEC).catch(() => {});
    t.ui.cancel("locked");
    expect(t.timers.pending.size).toBe(0);
    t.ui.ask(SPEC);
    expect(t.ok.disabled).toBe(true);
    expect(t.timers.pending.size).toBe(1);
  });
});

describe("wiersze potwierdzenia: związane vs od panelu (automatyczny przegląd bezpieczeństwa M-2)", () => {
  it("wiersze `bound` i `untrusted` dostają osobne klasy; etykieta nie zawija się (CSS nowrap)", () => {
    const t = setup();
    t.ui.ask({ ...SPEC, lines: ["Odcisk klucza odbiorcy: AAAA", "Odbiorca: …", "Porównaj…"], bound: [0], untrusted: [1] });
    expect(t.nodes["prompt-lines"].children.map((p) => p.className)).toEqual(["bound", "untrusted", ""]);
  });
});

it("vault.css: wiersz od panelu w jednej linii (bez zawijania), wiersz związany wyróżniony", async () => {
  const { readFileSync } = await import("node:fs");
  const css = readFileSync(new URL("../../src/vault.css", import.meta.url), "utf8").replace(/\s+/g, " ");
  expect(css).toMatch(/#prompt-lines p\.untrusted \{[^}]*white-space: nowrap;[^}]*\}/);
  expect(css).toMatch(/#prompt-lines p\.untrusted \{[^}]*text-overflow: ellipsis;[^}]*\}/);
  expect(css).toMatch(/#prompt-lines p\.bound \{[^}]*font-family: ui-monospace[^}]*\}/);
});

// Końcowy przegląd, M-5: potwierdzenie grantu każe porównać numer lekarza z tym, co odbiorca odczyta
// ze swojego sejfu — sejf pokazuje więc numer (związany przez AAD wrapu) obok odcisku.
it("po odblokowaniu: numer lekarza i odcisk; zablokowany: nic", () => {
  const t = setup();
  t.ui.render({ state: "unlocked", refusal: null, doctorId: 17, fingerprint: "AAAA BBBB", counters: null });
  expect(t.nodes.fingerprint.hidden).toBe(false);
  expect(t.nodes.fingerprint.textContent).toBe("Lekarz nr 17 · odcisk Twojego klucza: AAAA BBBB");
  t.ui.render({ state: "locked", refusal: null, doctorId: null, fingerprint: null, counters: null });
  expect(t.nodes.fingerprint.hidden).toBe(true);
  expect(t.nodes.fingerprint.textContent).toBe("");
});
