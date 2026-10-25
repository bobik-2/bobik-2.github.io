import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { random, utf8 } from "../../src/bytes.js";
import { dekInfo } from "../../src/crypto/context.js";
import { hpkeSeal } from "../../src/crypto/hpke.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { BOBIK2, b, bobik2ExpectedValues, bobik2OpenRequest } from "../helpers/vectors.js";
import { loadBobik2Clinic, makeVault, unlockFromVector } from "../helpers/vault.js";

const MIN = 60_000;
const stcItem = { kind: "stc", clinic_id: BOBIK2.clinic_id, field: BOBIK2.stc[0].field, blob: BOBIK2.stc[0].blob };

async function ready(opts) {
  const t = makeVault(opts);
  const S = await unlockFromVector(t);
  await loadBobik2Clinic(t, S);
  return t;
}

// Wywiady pod kluczem kliniki z bobik2_v1.json z losowym DEK — do testów limitu.
async function fakeInterviews(n) {
  const pub = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  const out = [];
  for (let i = 0; i < n; i++) {
    const id = crypto.randomUUID();
    const wrap = await hpkeSeal(pub, utf8(dekInfo(id)), random(32));
    out.push({ interview_id: id, interview_key_id: crypto.randomUUID(), clinic_key_id: BOBIK2.clinic_key_id, clinic_wrap: toB64url(wrap) });
  }
  return out;
}

describe("open z wektorami bobik2_v1.json (V-1, V-6)", () => {
  it("Sealed, SealedToClinic i przypadki negatywne, w kolejności items", async () => {
    const t = await ready();
    expect(await t.ok("open", bobik2OpenRequest())).toEqual({ values: bobik2ExpectedValues() });
    expect(t.vault.keys()).toHaveLength(3); // lekarz, klinika, DEK
    expect(t.vault.keys().every((k) => k.extractable === false)).toBe(true);
    expect(t.vault.view().counters.interviews).toBe(1);
  });

  it("puste żądanie -> pusta lista", async () => {
    const t = await ready();
    expect(await t.ok("open", { interviews: [], items: [] })).toEqual({ values: [] });
  });
});

describe("open: błędy per element i bad_args (Review Focus 3)", () => {
  it("element sealed bez wpisu w interviews -> unknown_interview", async () => {
    const t = await ready();
    const { items } = bobik2OpenRequest();
    expect(await t.ok("open", { interviews: [], items: [items[0]] })).toEqual({ values: [{ ok: false, error: "unknown_interview" }] });
  });

  it("wywiad z niezaładowanym kluczem kliniki -> clinic_key_not_loaded dla jego pól", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    const interviews = [{ ...req.interviews[0], clinic_key_id: "00000000-0000-4000-8000-000000000001" }];
    expect((await t.ok("open", { interviews, items: [req.items[0]] })).values).toEqual([{ ok: false, error: "clinic_key_not_loaded" }]);
  });

  it("clinic_wrap innego wywiadu -> decrypt_failed dla jego pól", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    const [other] = await fakeInterviews(1);
    const interviews = [{ ...req.interviews[0], clinic_wrap: other.clinic_wrap }];
    expect((await t.ok("open", { interviews, items: [req.items[0]] })).values).toEqual([{ ok: false, error: "decrypt_failed" }]);
  });

  it("STC: klucz z nagłówka należy do innej kliniki -> key_mismatch", async () => {
    const t = await ready();
    expect((await t.ok("open", { interviews: [], items: [{ ...stcItem, clinic_id: BOBIK2.clinic_id + 1 }] })).values).toEqual([{ ok: false, error: "key_mismatch" }]);
  });

  it("STC: nagłówek wskazuje niezaładowany klucz kliniki -> clinic_key_not_loaded", async () => {
    const t = await ready();
    const blob = b(stcItem.blob);
    blob.fill(0, 1, 17);
    expect((await t.ok("open", { interviews: [], items: [{ ...stcItem, blob: toB64url(blob) }] })).values).toEqual([{ ok: false, error: "clinic_key_not_loaded" }]);
  });

  it("ucięty Sealed -> bad_blob", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    const item = { ...req.items[0], blob: toB64url(b(req.items[0].blob).slice(0, 20)) };
    expect((await t.ok("open", { interviews: req.interviews, items: [item] })).values).toEqual([{ ok: false, error: "bad_blob" }]);
  });

  it.each([
    ["powtórzony interview_id", (r) => { r.interviews.push({ ...r.interviews[0] }); }],
    ["blob null (pole puste w ciphertexts — panel je pomija, P5)", (r) => { r.items[0].blob = null; }],
    ["element sealed bez interview_id", (r) => { delete r.items[0].interview_id; }],
    ["zły field", (r) => { r.items[0].field = "x"; }],
    ["zły kind", (r) => { r.items[0].kind = "dek"; }],
    ["> 1000 elementów", (r) => { r.items = Array(1001).fill(stcItem); }],
    ["interviews nie jest tablicą", (r) => { r.interviews = {}; }],
    ["clinic_id tekstem", (r) => { r.items[3].clinic_id = "3"; }],
  ])("%s -> bad_args", async (_name, mutate) => {
    const t = await ready();
    const req = bobik2OpenRequest();
    mutate(req);
    expect(await t.call("open", req)).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("ponowne otwarcie z innym interview_key_id: DEK odpakowany ponownie, stare bloby -> key_mismatch, licznik bez zmian", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    expect((await t.ok("open", { interviews: req.interviews, items: [req.items[0]] })).values[0]).toMatchObject({ ok: true });
    const rekeyed = { ...req.interviews[0], interview_key_id: "99999999-8888-4777-8666-555555555555" };
    expect((await t.ok("open", { interviews: [rekeyed], items: [req.items[0]] })).values).toEqual([{ ok: false, error: "key_mismatch" }]);
    expect(t.vault.view().counters.interviews).toBe(1);
  });
});

describe("limit w open (V-5)", () => {
  it("10 nowych wywiadów przechodzi, 11. -> rate_limited bez blokady; po 5 min znów można", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    const iv = await fakeInterviews(11);
    expect(await t.ok("open", { interviews: iv.slice(0, 10), items: [] })).toEqual({ values: [] });
    expect(await t.call("open", { interviews: [iv[10]], items: [] })).toMatchObject({ ok: false, error: "rate_limited" });
    expect(t.events).toEqual([]);
    expect(await t.ok("open", { interviews: iv.slice(0, 10), items: [] })).toEqual({ values: [] }); // DEK w pamięci: bez kosztu
    clock.t += 5 * MIN;
    expect(await t.call("open", { interviews: [iv[10]], items: [] })).toMatchObject({ ok: true });
    expect(t.ui.views.at(-1).counters).toMatchObject({ interviews: 11 });
  });

  it("51. wywiad -> limit_reached, auto-blokada, zdarzenie locked/limit, klucze usunięte", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    const iv = await fakeInterviews(51);
    for (let r = 0; r < 5; r++) {
      await t.ok("open", { interviews: iv.slice(r * 10, r * 10 + 10), items: [] });
      clock.t += 5 * MIN;
    }
    expect(t.vault.view().counters.interviews).toBe(50);
    expect(await t.call("open", { interviews: [iv[50]], items: [] })).toMatchObject({ ok: false, error: "limit_reached" });
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "limit" }]);
    expect(t.vault.keys()).toEqual([]);
    expect(await t.call("open", { interviews: [], items: [] })).toMatchObject({ ok: false, error: "locked" });
  }, 30_000);

  it("STC: 100 na minutę -> rate_limited; 501. w sesji -> limit_reached", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    const hundred = Array(100).fill(stcItem);
    expect((await t.ok("open", { interviews: [], items: hundred })).values).toHaveLength(100);
    expect(await t.call("open", { interviews: [], items: [stcItem] })).toMatchObject({ ok: false, error: "rate_limited" });
    for (let i = 0; i < 4; i++) {
      clock.t += MIN;
      await t.ok("open", { interviews: [], items: hundred });
    }
    clock.t += MIN;
    expect(await t.call("open", { interviews: [], items: [stcItem] })).toMatchObject({ ok: false, error: "limit_reached" });
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "limit" }]);
  }, 60_000);

  it("bezczynność 15 min -> tick blokuje (idle)", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    clock.t += 15 * MIN;
    t.vault.tick();
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "idle" }]);
    expect(t.vault.keys()).toEqual([]);
  });

  it("wiek 8 h -> max_age mimo aktywności", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    for (let i = 1; i < 48; i++) {
      clock.t += 10 * MIN;
      await t.ok("open", { interviews: [], items: [] });
      t.vault.tick();
    }
    expect(t.events).toEqual([]);
    clock.t += 10 * MIN;
    t.vault.tick();
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "max_age" }]);
  });
});
