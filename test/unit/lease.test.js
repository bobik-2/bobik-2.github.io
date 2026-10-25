import { describe, expect, it } from "vitest";
import { importLeaseKey, RSA_WRAPPED_DEK_LEN, wrapDekForLease } from "../../src/crypto/lease.js";
import { BOBIK2, b } from "../helpers/vectors.js";

async function rsaSpki(modulusLength, publicExponent) {
  const key = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength, publicExponent: Uint8Array.from(publicExponent), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  return new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
}

describe("F6: DEK dla dzierżawy (V-7)", () => {
  it("klucz RSA-3072 z bobik2_v1.json: 384 B, otwiera go klucz prywatny dzierżawy, bufor DEK wyzerowany", async () => {
    const key = await importLeaseKey(b(BOBIK2.rsa_lease_key.public_key_spki_der));
    const dek = b(BOBIK2.dek);
    const wrapped = await wrapDekForLease(key, dek);
    expect(wrapped).toHaveLength(RSA_WRAPPED_DEK_LEN);
    expect(dek.every((x) => x === 0)).toBe(true);
    const priv = await crypto.subtle.importKey(
      "pkcs8",
      b(BOBIK2.rsa_lease_key.private_key_pkcs8_der),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );
    expect(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, wrapped))).toEqual(b(BOBIK2.dek));
  });

  it("RSA-2048 -> bad_lease_key", async () => {
    await expect(importLeaseKey(await rsaSpki(2048, [1, 0, 1]))).rejects.toMatchObject({ code: "bad_lease_key" });
  });

  it("RSA-3072 z e = 3 -> bad_lease_key", async () => {
    await expect(importLeaseKey(await rsaSpki(3072, [3]))).rejects.toMatchObject({ code: "bad_lease_key" });
  }, 30_000);

  it.each([
    ["klucz EC", () => b(BOBIK2.clinic.public_key_spki_der)],
    ["śmieci", () => new Uint8Array(300).fill(1)],
  ])("%s -> bad_lease_key", async (_name, der) => {
    await expect(importLeaseKey(der())).rejects.toMatchObject({ code: "bad_lease_key" });
  });
});
