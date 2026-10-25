import { describe, expect, it } from "vitest";
import { bytes, field, label, LABEL_MAX, list, oneOf, optPosInt, posInt, uuid } from "../../src/validate.js";

const bad = expect.objectContaining({ code: "bad_args" });

describe("walidatory bad_args (spec B, „Walidacja argumentów”)", () => {
  it("posInt: dodatnie liczby całkowite", () => {
    expect(posInt(17)).toBe(17);
    for (const v of [0, -1, 1.5, "17", null, undefined, true, Number.MAX_SAFE_INTEGER + 1]) expect(() => posInt(v)).toThrow(bad);
  });

  it("optPosInt: null albo posInt; brak klucza to błąd", () => {
    expect(optPosInt(null)).toBe(null);
    expect(optPosInt(2)).toBe(2);
    expect(() => optPosInt(undefined)).toThrow(bad);
  });

  it("uuid: małe litery z myślnikami", () => {
    expect(uuid("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b")).toBe("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b");
    for (const v of ["3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B", "3f2a9c1e5b7d4e8f9a0b1c2d3e4f5a6b", "", 42]) expect(() => uuid(v)).toThrow(bad);
  });

  it("field: app_label.Model.pole", () => {
    for (const v of ["interviews.Interview.first_name", "core.WithdrawalLog.reason"]) expect(field(v)).toBe(v);
    for (const v of ["Interviews.Interview.age", "interviews.Interview", "interviews.Interview.Age", "a.b.c|x", 1]) expect(() => field(v)).toThrow(bad);
  });

  it("label: 1..max znaków", () => {
    expect(label("a", 3)).toBe("a");
    for (const v of ["", "abcd", 5, null]) expect(() => label(v, 3)).toThrow(bad);
  });

  // Przegląd 9–10, M-2: etykieta od panelu nie może podrobić osobnego wiersza potwierdzenia
  // (np. „Odcisk klucza odbiorcy: …”) ani odwrócić kolejności znaków.
  it("label: domyślnie maks. 80 znaków, polskie litery i interpunkcja przechodzą", () => {
    expect(LABEL_MAX).toBe(80);
    const name = "dr hab. n. med. Żaneta Łęcka-Ślązak (Klinika Anestezjologii, OIT) — I piętro";
    expect(name.length).toBeLessThanOrEqual(80);
    expect(label(name)).toBe(name);
    expect(label("x".repeat(80))).toBe("x".repeat(80));
    expect(() => label("x".repeat(81))).toThrow(bad);
  });

  it.each([
    ["nowa linia", "dr V\nOdcisk klucza odbiorcy: AAAA"],
    ["CR", "dr V\r"],
    ["tabulator", "dr\tV"],
    ["NUL", "dr\u0000V"],
    ["DEL", "dr\u007fV"],
    ["U+0085 (NEL)", "dr\u0085V"],
    ["U+2028 (separator wierszy)", "dr V\u2028Odcisk klucza odbiorcy: AAAA"],
    ["U+2029 (separator akapitów)", "dr V\u2029x"],
    ["U+202E (bidi RLO)", "dr \u202eV"],
    ["U+2066 (bidi LRI)", "dr \u2066V"],
    ["U+200B (spacja zerowej szerokości)", "dr\u200bV"],
    ["U+FEFF (BOM)", "\ufeffdr V"],
  ])("label: %s -> bad_args", (_name, v) => {
    expect(() => label(v)).toThrow(bad);
  });

  it("oneOf", () => {
    expect(oneOf("repair", ["addendum", "repair"])).toBe("repair");
    expect(() => oneOf("x", ["a"])).toThrow(bad);
  });

  it("bytes: base64url bez paddingu, długość w granicach", () => {
    expect(bytes("AQI", { min: 2, max: 2 })).toEqual(Uint8Array.of(1, 2));
    for (const v of ["AQI=", "A+I", "AQ", null, 3]) expect(() => bytes(v, { min: 2, max: 2 })).toThrow(bad);
  });

  it("list: tablica obiektów o liczności min..max", () => {
    expect(list([{ a: 1 }], { max: 2 }, (x) => x.a)).toEqual([1]);
    for (const v of [null, {}, [1], [[]], [{}, {}, {}]]) expect(() => list(v, { max: 2 }, (x) => x)).toThrow(bad);
    expect(() => list([], { min: 1, max: 2 }, (x) => x)).toThrow(bad);
  });
});
