import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../src/bytes.js";
import { generateClinicKey, GRANT_VERSION, openClinicGrant, sealClinicGrant } from "../../src/crypto/clinic.js";
import { generateDoctorKey } from "../../src/crypto/doctor.js";
import { importP256Pair, importP256Public } from "../../src/crypto/keys.js";

// Para lekarza jak w sejfie po unlock: prywatny nieeksportowalny + publiczny.
async function doctorPair() {
  const { pair, spki } = await generateDoctorKey();
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return importP256Pair(pkcs8, await importP256Public(spki));
}

async function setup() {
  const recipient = await doctorPair();
  const clinic = await generateClinicKey();
  const ctx = { clinicId: 3, doctorId: 17, clinicSpkiHex: await sha256Hex(clinic.spki) };
  const blob = await sealClinicGrant(recipient.publicKey, { ...ctx, pkcs8: clinic.pkcs8.slice() });
  return { recipient, clinic, ctx, blob };
}

describe("F4: grant klucza kliniki", () => {
  it("generateClinicKey: SPKI P-256 (91 B) i PKCS8", async () => {
    const { spki, pkcs8 } = await generateClinicKey();
    expect(spki).toHaveLength(91);
    expect((await importP256Public(spki)).algorithm.namedCurve).toBe("P-256");
    expect(pkcs8.length).toBeGreaterThan(100);
  });

  it("grant = [0x01][enc 65 B][szyfrogram ‖ tag]; otwiera go para odbiorcy", async () => {
    const s = await setup();
    expect(s.blob[0]).toBe(GRANT_VERSION);
    expect(s.blob).toHaveLength(1 + 65 + s.clinic.pkcs8.length + 16);
    expect(await openClinicGrant(s.recipient, { ...s.ctx, blob: s.blob })).toEqual(s.clinic.pkcs8);
  });

  it.each([
    ["inny clinic_id", async (s) => ({ ...s.ctx, clinicId: 4 })],
    ["inny doctor_id", async (s) => ({ ...s.ctx, doctorId: 18 })],
    ["podmieniony SPKI kliniki (B-D4)", async (s) => ({ ...s.ctx, clinicSpkiHex: await sha256Hex((await generateClinicKey()).spki) })],
  ])("%s -> unwrap_failed", async (_name, change) => {
    const s = await setup();
    await expect(openClinicGrant(s.recipient, { ...(await change(s)), blob: s.blob })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("para innego lekarza -> unwrap_failed", async () => {
    const s = await setup();
    await expect(openClinicGrant(await doctorPair(), { ...s.ctx, blob: s.blob })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it.each([
    ["zły bajt wersji", (blob) => { const x = blob.slice(); x[0] = 2; return x; }],
    ["za krótki (< 82 B)", (blob) => blob.slice(0, 81)],
  ])("%s -> unwrap_failed", async (_name, mutate) => {
    const s = await setup();
    await expect(openClinicGrant(s.recipient, { ...s.ctx, blob: mutate(s.blob) })).rejects.toMatchObject({ code: "unwrap_failed" });
  });
});
