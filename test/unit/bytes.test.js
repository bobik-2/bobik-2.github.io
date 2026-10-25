import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { bytesToUuid, concat, hex, random, sha256Hex, utf8 } from "../../src/bytes.js";

it("concat, hex, utf8", () => {
  expect(concat(Uint8Array.of(1), Uint8Array.of(2, 255))).toEqual(Uint8Array.of(1, 2, 255));
  expect(hex(Uint8Array.of(0, 15, 255))).toBe("000fff");
  expect(utf8("ż")).toEqual(Uint8Array.of(0xc5, 0xbc));
});

it("sha256Hex = SHA-256, 64 znaki hex małymi literami", async () => {
  const data = utf8("abc");
  expect(await sha256Hex(data)).toBe(createHash("sha256").update(data).digest("hex"));
});

it("bytesToUuid: 16 B -> UUID z myślnikami; inna długość -> RangeError", () => {
  const bytes = Uint8Array.from("66666666777748889999aaaaaaaaaaaa".match(/../g), (h) => parseInt(h, 16));
  expect(bytesToUuid(bytes)).toBe("66666666-7777-4888-9999-aaaaaaaaaaaa");
  expect(() => bytesToUuid(new Uint8Array(15))).toThrow(RangeError);
});

it("random(n) daje n losowych bajtów", () => {
  expect(random(32)).toHaveLength(32);
  expect(random(32)).not.toEqual(random(32));
});
