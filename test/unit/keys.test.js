import { expect, it } from "vitest";
import { importP256Pair, importP256Public } from "../../src/crypto/keys.js";
import { BOBIK2, b } from "../helpers/vectors.js";

it("importP256Public: SPKI P-256 kliniki z bobik-2", async () => {
  const key = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  expect(key.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });
});

it.each([
  ["RSA-3072", () => b(BOBIK2.rsa_lease_key.public_key_spki_der)],
  ["śmieci", () => new Uint8Array(91).fill(7)],
])("importP256Public: %s -> bad_key", async (_name, der) => {
  await expect(importP256Public(der())).rejects.toMatchObject({ code: "bad_key" });
});

it("importP256Pair: prywatny nieeksportowalny, publiczny obok, bufor PKCS8 wyzerowany", async () => {
  const pkcs8 = b(BOBIK2.clinic.private_key_pkcs8_der);
  const publicKey = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  const pair = await importP256Pair(pkcs8, publicKey);
  expect(pair.privateKey.extractable).toBe(false);
  expect(pair.publicKey).toBe(publicKey);
  expect(pkcs8.every((x) => x === 0)).toBe(true);
});

it("importP256Pair: PKCS8 nie-P-256 -> unwrap_failed, bufor i tak wyzerowany", async () => {
  const pkcs8 = b(BOBIK2.rsa_lease_key.private_key_pkcs8_der);
  const publicKey = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  await expect(importP256Pair(pkcs8, publicKey)).rejects.toMatchObject({ code: "unwrap_failed" });
  expect(pkcs8.every((x) => x === 0)).toBe(true);
});
