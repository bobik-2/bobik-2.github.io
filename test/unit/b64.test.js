import { expect, it } from "vitest";
import { fromB64url, toB64url } from "../../src/b64.js";

it("base64url w obie strony, bez paddingu", () => {
  const bytes = new Uint8Array([0, 251, 255, 1, 2]);
  expect(toB64url(bytes)).toBe("APv_AQI");
  expect(fromB64url("APv_AQI")).toEqual(bytes);
  expect(toB64url(bytes.buffer)).toBe("APv_AQI");
});

it("odrzuca znaki spoza alfabetu", () => {
  expect(() => fromB64url("a+b/")).toThrow();
});
