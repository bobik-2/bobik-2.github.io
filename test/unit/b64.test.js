import { expect, it } from "vitest";
import { B64Error, fromB64url, toB64url } from "../../src/b64.js";

it("base64url w obie strony, bez paddingu", () => {
  const bytes = new Uint8Array([0, 251, 255, 1, 2]);
  expect(toB64url(bytes)).toBe("APv_AQI");
  expect(fromB64url("APv_AQI")).toEqual(bytes);
  expect(toB64url(bytes.buffer)).toBe("APv_AQI");
});

it("odrzuca znaki spoza alfabetu, padding, długość 4k+1 i nie-tekst", () => {
  for (const bad of ["a+b/", "QQ==", "Q", "AAAAA", 12, null, undefined]) {
    expect(() => fromB64url(bad)).toThrow(B64Error);
  }
});
