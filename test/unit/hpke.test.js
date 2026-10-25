import { expect, it } from "vitest";
import { utf8 } from "../../src/bytes.js";
import { ENC_LEN, hpkeOpen, hpkeSeal, isHpkeFailure } from "../../src/crypto/hpke.js";

const P256 = { name: "ECDH", namedCurve: "P-256" };

// Para jak w sejfie: prywatny nieeksportowalny, publiczny obok (spike, pułapka znaku y).
async function pair() {
  const g = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", g.privateKey);
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, P256, false, ["deriveBits"]);
  return { privateKey, publicKey: g.publicKey };
}

it("seal/open parą z nieeksportowalnym kluczem prywatnym działa dla 8 świeżych kluczy (oba znaki y)", async () => {
  for (let i = 0; i < 8; i++) {
    const p = await pair();
    const blob = await hpkeSeal(p.publicKey, utf8("info"), utf8("tresc"));
    expect(blob).toHaveLength(ENC_LEN + 5 + 16);
    expect(new TextDecoder().decode(await hpkeOpen(p, utf8("info"), blob))).toBe("tresc");
  }
});

it("inny info -> błąd rozpoznawany przez isHpkeFailure", async () => {
  const p = await pair();
  const blob = await hpkeSeal(p.publicKey, utf8("a"), utf8("x"));
  const err = await hpkeOpen(p, utf8("b"), blob).catch((e) => e);
  expect(isHpkeFailure(err)).toBe(true);
});

it("zwykły wyjątek nie jest błędem HPKE", () => {
  expect(isHpkeFailure(new TypeError("x"))).toBe(false);
});
