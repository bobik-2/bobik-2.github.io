import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { concat, utf8 } from "../../src/bytes.js";
import { sealedContext } from "../../src/crypto/context.js";
import { importDek, openClinicWrap, openSealed, openStc, sealedKeyId, stcKeyId } from "../../src/crypto/fields.js";
import { BOBIK2, b, bobik2ClinicPair } from "../helpers/vectors.js";

async function dekKey() {
  return importDek(await openClinicWrap(await bobik2ClinicPair(), BOBIK2.interview_id, b(BOBIK2.clinic_wrap.blob)));
}
const sealedArgs = (s) => ({ interviewId: BOBIK2.interview_id, interviewKeyId: BOBIK2.interview_key_id, field: s.field, blob: b(s.blob) });

describe("F5 z wektorami bobik2_v1.json (V-1)", () => {
  it("clinic_wrap otwiera się parą kliniki i daje DEK z wektora", async () => {
    const dek = await openClinicWrap(await bobik2ClinicPair(), BOBIK2.interview_id, b(BOBIK2.clinic_wrap.blob));
    expect(toB64url(dek)).toBe(BOBIK2.dek);
  });

  it("clinic_wrap z innym interview_id w info -> decrypt_failed", async () => {
    const other = "00000000-0000-4000-8000-000000000000";
    await expect(openClinicWrap(await bobik2ClinicPair(), other, b(BOBIK2.clinic_wrap.blob))).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("clinic_wrap o złej długości -> bad_blob", async () => {
    const short = b(BOBIK2.clinic_wrap.blob).slice(1);
    await expect(openClinicWrap(await bobik2ClinicPair(), BOBIK2.interview_id, short)).rejects.toMatchObject({ code: "bad_blob" });
  });

  it.each(BOBIK2.sealed.map((s) => [s.field, s]))("Sealed %s", async (_field, s) => {
    expect(await openSealed(await dekKey(), sealedArgs(s))).toEqual(s.value);
  });

  it.each(BOBIK2.stc.map((s) => [s.field, s]))("SealedToClinic %s", async (_field, s) => {
    expect(stcKeyId(b(s.blob))).toBe(BOBIK2.clinic_key_id);
    expect(await openStc(await bobik2ClinicPair(), { clinicId: BOBIK2.clinic_id, field: s.field, blob: b(s.blob) })).toEqual(s.value);
  });

  it.each(BOBIK2.negative.map((n) => [n.case, n]))("przypadek negatywny %s -> kod z wektora", async (_case, n) => {
    const run =
      n.kind === "sealed"
        ? openSealed(await dekKey(), { interviewId: n.interview_id, interviewKeyId: BOBIK2.interview_key_id, field: n.field, blob: b(n.blob) })
        : openStc(await bobik2ClinicPair(), { clinicId: n.clinic_id, field: n.field, blob: b(n.blob) });
    await expect(run).rejects.toMatchObject({ code: n.error });
  });
});

describe("format kopert i bufory", () => {
  it("sealedKeyId czyta InterviewKey.id z nagłówka", () => {
    expect(sealedKeyId(b(BOBIK2.sealed[0].blob))).toBe(BOBIK2.interview_key_id);
  });

  it.each([
    ["zły bajt wersji", (x) => { x[0] = 0x02; return x; }],
    ["za krótki", (x) => x.slice(0, 40)],
  ])("Sealed: %s -> bad_blob", async (_name, mutate) => {
    const blob = mutate(b(BOBIK2.sealed[0].blob));
    await expect(openSealed(await dekKey(), { ...sealedArgs(BOBIK2.sealed[0]), blob })).rejects.toMatchObject({ code: "bad_blob" });
  });

  it("SealedToClinic: zły bajt wersji -> bad_blob", () => {
    const blob = b(BOBIK2.stc[0].blob);
    blob[0] = 0x01;
    expect(() => stcKeyId(blob)).toThrow(expect.objectContaining({ code: "bad_blob" }));
  });

  it("importDek: DEK nieeksportowalny, bufor wyzerowany", async () => {
    const raw = b(BOBIK2.dek);
    const key = await importDek(raw);
    expect(key.extractable).toBe(false);
    expect(raw.every((x) => x === 0)).toBe(true);
  });

  it("tekst jawny, który nie jest JSON-em -> bad_blob (P15)", async () => {
    const field = "interviews.Interview.first_name";
    const header = b(BOBIK2.sealed[0].blob).slice(0, 17);
    const nonce = new Uint8Array(12).fill(1);
    const enc = await crypto.subtle.importKey("raw", b(BOBIK2.dek), "AES-GCM", false, ["encrypt"]);
    const aad = concat(header, utf8(`|${sealedContext(BOBIK2.interview_id, field)}`));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, enc, utf8("nie-json")));
    const args = { interviewId: BOBIK2.interview_id, interviewKeyId: BOBIK2.interview_key_id, field, blob: concat(header, nonce, ct) };
    await expect(openSealed(await dekKey(), args)).rejects.toMatchObject({ code: "bad_blob" });
  });
});
