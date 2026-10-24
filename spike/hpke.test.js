// SPIKE (throwaway): czy @hpke/core otwiera szyfrogramy bobik-2 kluczem
// prywatnym kliniki jako NIEEKSPORTOWALNY CryptoKey?
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { Aes256Gcm, CipherSuite, DhkemP256HkdfSha256, HkdfSha256 } from "@hpke/core";

const v = JSON.parse(readFileSync(new URL("./vectors.json", import.meta.url)));
const b = (s) => Uint8Array.from(Buffer.from(s, "base64url"));
const te = new TextEncoder();
const subtle = globalThis.crypto.subtle;
const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

async function clinicPair() {
  const privateKey = await subtle.importKey("pkcs8", b(v.clinic_private_pkcs8), { name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const publicKey = await subtle.importKey("spki", b(v.clinic_public_spki), { name: "ECDH", namedCurve: "P-256" }, true, []);
  return { privateKey, publicKey };
}

async function hpkeOpen(recipientKey, info, blob) {
  const r = await suite.createRecipientContext({ recipientKey, enc: blob.slice(0, 65), info });
  return new Uint8Array(await r.open(blob.slice(65)));
}

it("klucz prywatny jest nieeksportowalny", async () => {
  const { privateKey } = await clinicPair();
  expect(privateKey.extractable).toBe(false);
  await expect(subtle.exportKey("pkcs8", privateKey)).rejects.toThrow();
});

it("sam CryptoKey (bez pary): @hpke zgaduje znak y klucza publicznego -> działa tylko dla parzystego y", async () => {
  const { privateKey } = await clinicPair();
  const spki = b(v.clinic_public_spki);
  const yEven = (spki[spki.length - 1] & 1) === 0;
  const attempt = hpkeOpen(privateKey, te.encode(`bobik/dek/v1|interview=${v.interview_id}`), b(v.clinic_wrap));
  if (yEven) await expect(attempt).resolves.toBeDefined();
  else await expect(attempt).rejects.toThrow();
});

it("clinic_wrap -> DEK -> Sealed (para z nieeksportowalnym prywatnym)", async () => {
  const pair = await clinicPair();
  const dek = await hpkeOpen(pair, te.encode(`bobik/dek/v1|interview=${v.interview_id}`), b(v.clinic_wrap));
  expect(Buffer.from(dek).toString("base64url")).toBe(v.dek);

  const sealed = b(v.sealed);
  const header = sealed.slice(0, 17);
  const aad = new Uint8Array([...header, ...te.encode(`|interview=${v.interview_id}|field=${v.field}`)]);
  const dekKey = await subtle.importKey("raw", dek, "AES-GCM", false, ["decrypt"]);
  dek.fill(0);
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: sealed.slice(17, 29), additionalData: aad }, dekKey, sealed.slice(29));
  expect(JSON.parse(new TextDecoder().decode(pt))).toEqual(JSON.parse(v.plaintext));
});

it("SealedToClinic", async () => {
  const pair = await clinicPair();
  const stc = b(v.stc);
  const header = stc.slice(0, 17);
  const info = new Uint8Array([...te.encode("bobik/stc/v1|"), ...header, ...te.encode(`|clinic=${v.clinic_id}|field=${v.field}`)]);
  const pt = await hpkeOpen(pair, info, stc.slice(17));
  expect(new TextDecoder().decode(pt)).toBe(v.plaintext);
});

it("zły info -> błąd (kontekst jest wiązany)", async () => {
  const pair = await clinicPair();
  await expect(hpkeOpen(pair, te.encode(`bobik/dek/v1|interview=43`), b(v.clinic_wrap))).rejects.toThrow();
});
