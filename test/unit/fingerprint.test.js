import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { base32, fingerprint } from "../../src/fingerprint.js";

it("base32 RFC 4648 bez paddingu", () => {
  const te = new TextEncoder();
  expect(base32(te.encode("foobar"))).toBe("MZXW6YTBOI");
  expect(base32(te.encode("f"))).toBe("MY");
});

it("odcisk = SHA-256, pierwsze 20 B, base32, 8 grup po 4", async () => {
  const data = new TextEncoder().encode("klucz");
  const fp = await fingerprint(data);
  expect(fp).toMatch(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
  const expected = base32(createHash("sha256").update(data).digest().subarray(0, 20));
  expect(fp.replaceAll(" ", "")).toBe(expected);
});
