import { describe, expect, it } from "vitest";
import { bytes, field, list, oneOf, optPosInt, posInt, text, uuid } from "../../src/validate.js";

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

  it("text: 1..max znaków", () => {
    expect(text("a", 3)).toBe("a");
    for (const v of ["", "abcd", 5, null]) expect(() => text(v, 3)).toThrow(bad);
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
