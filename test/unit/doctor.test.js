import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { random, sha256Hex } from "../../src/bytes.js";
import { doctorWrapAad } from "../../src/crypto/context.js";
import { deriveKek, generateDoctorKey, unwrapDoctorKey, WRAP_VERSION, wrapDoctorKey } from "../../src/crypto/doctor.js";

const DOCTOR = 17;

async function setup() {
  const { pair, spki } = await generateDoctorKey();
  const spkiHex = await sha256Hex(spki);
  const credential = toB64url(random(16));
  const prf = random(32);
  const kek = await deriveKek(prf.slice(), DOCTOR, credential);
  const blob = await wrapDoctorKey(pair.privateKey, kek, doctorWrapAad(DOCTOR, credential, spkiHex));
  return { pair, spki, spkiHex, credential, prf, blob };
}

async function unwrap(s, { prf = s.prf, doctor = DOCTOR, credential = s.credential, spkiHex = s.spkiHex, blob = s.blob, extractable } = {}) {
  const kek = await deriveKek(prf.slice(), doctor, credential);
  return unwrapDoctorKey(blob, kek, doctorWrapAad(doctor, credential, spkiHex), { extractable });
}

describe("F1–F3: klucz pakujący i wrap klucza lekarza", () => {
  it("generateDoctorKey: para ECDH P-256 i SPKI DER (91 B)", async () => {
    const { pair, spki } = await generateDoctorKey();
    expect(pair.privateKey.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });
    expect(spki).toHaveLength(91);
  });

  it("deriveKek zeruje wynik PRF i daje nieeksportowalny AES-256-GCM do wrapKey/unwrapKey", async () => {
    const prf = random(32);
    const kek = await deriveKek(prf, DOCTOR, "AQ");
    expect(prf.every((x) => x === 0)).toBe(true);
    expect(kek.extractable).toBe(false);
    expect(kek.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect([...kek.usages].sort()).toEqual(["unwrapKey", "wrapKey"]);
  });

  it("wrap = [0x01][iv 12 B][szyfrogram ‖ tag], 29–1024 B (walidator B2)", async () => {
    const s = await setup();
    expect(s.blob[0]).toBe(WRAP_VERSION);
    expect(s.blob.length).toBeGreaterThanOrEqual(29);
    expect(s.blob.length).toBeLessThanOrEqual(1024);
  });

  it("unwrap tym samym PRF i kontekstem daje nieeksportowalny klucz ECDH P-256", async () => {
    const key = await unwrap(await setup());
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });
  });

  it("unwrap z extractable: true (add_credential) daje klucz, który da się zapakować ponownie", async () => {
    const key = await unwrap(await setup(), { extractable: true });
    const kek2 = await deriveKek(random(32), DOCTOR, "Ag");
    expect((await wrapDoctorKey(key, kek2, "aad"))[0]).toBe(WRAP_VERSION);
  });

  it.each([
    ["inny wynik PRF (inny YubiKey)", async () => ({ prf: random(32) })],
    ["inny doctor_id", async () => ({ doctor: 18 })],
    ["inny credential", async () => ({ credential: toB64url(random(16)) })],
    ["podmieniony SPKI lekarza (B-D4)", async () => ({ spkiHex: await sha256Hex((await generateDoctorKey()).spki) })],
    ["zły bajt wersji", async (s) => { const blob = s.blob.slice(); blob[0] = 2; return { blob }; }],
    ["za krótki", async (s) => ({ blob: s.blob.slice(0, 28) })],
    ["przekłamany bajt szyfrogramu", async (s) => { const blob = s.blob.slice(); blob[20] ^= 1; return { blob }; }],
  ])("%s -> unwrap_failed", async (_name, change) => {
    const s = await setup();
    await expect(unwrap(s, await change(s))).rejects.toMatchObject({ code: "unwrap_failed" });
  });
});
