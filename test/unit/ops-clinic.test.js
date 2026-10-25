import { describe, expect, it } from "vitest";
import { fromB64url, toB64url } from "../../src/b64.js";
import { generateClinicKey } from "../../src/crypto/clinic.js";
import { fakeUi } from "../helpers/fake-ui.js";
import { BOBIK2 } from "../helpers/vectors.js";
import { loadBobik2Clinic, makeVault, registerDoctor, unlockDoctor, unlockFromVector } from "../helpers/vault.js";

const NEW_KEY_ID = "0b6f7a52-1c1e-4a7e-9d43-2a1f5e8c9d10";
const JUNK_KEY = toB64url(new Uint8Array(91).fill(7));

describe("load_clinic_key (F4, V-1, V-6)", () => {
  it("grant z sejf_v1.json otwiera klucz kliniki z bobik2_v1.json; odcisk = odcisk z bobik-2", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    expect(await loadBobik2Clinic(t, S)).toEqual({ clinic_key_id: BOBIK2.clinic_key_id, fingerprint: BOBIK2.clinic.fingerprint });
    expect(t.vault.keys()).toHaveLength(2);
    expect(t.vault.keys().every((k) => k.extractable === false)).toBe(true);
  });

  it.each([
    ["inny clinic_id (info grantu)", async () => ({ clinic_id: BOBIK2.clinic_id + 1 })],
    ["inny klucz publiczny kliniki (B-D4)", async () => ({ clinic_public_key_der: toB64url((await generateClinicKey()).spki) })],
  ])("%s -> unwrap_failed", async (_name, change) => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    const args = {
      clinic_id: BOBIK2.clinic_id,
      clinic_key_id: BOBIK2.clinic_key_id,
      clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
      wrapped_private: S.clinic_grant.wrapped_private,
      ...(await change()),
    };
    expect(await t.call("load_clinic_key", args)).toMatchObject({ ok: false, error: "unwrap_failed" });
  });

  it("klucz publiczny kliniki nie-P-256 -> bad_key; grant < 82 B -> bad_args", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    const base = { clinic_id: BOBIK2.clinic_id, clinic_key_id: BOBIK2.clinic_key_id, clinic_public_key_der: BOBIK2.clinic.public_key_spki_der, wrapped_private: S.clinic_grant.wrapped_private };
    expect(await t.call("load_clinic_key", { ...base, clinic_public_key_der: JUNK_KEY })).toMatchObject({ ok: false, error: "bad_key" });
    expect(await t.call("load_clinic_key", { ...base, wrapped_private: "AQID" })).toMatchObject({ ok: false, error: "bad_args" });
  });
});

describe("create_clinic_key (F4)", () => {
  it("potwierdzenie z etykietą, grant dla siebie; do pamięci dopiero przez load_clinic_key", async () => {
    const t = makeVault();
    await unlockFromVector(t);
    const created = await t.ok("create_clinic_key", { clinic_id: 5, clinic_label: "Klinika Testowa" });
    const prompt = t.ui.prompts.at(-1);
    expect(prompt.kind).toBe("create_clinic");
    expect(prompt.lines.slice(0, 2)).toEqual(["Klinika nr 5", "Nazwa kliniki z panelu (niezweryfikowana): Klinika Testowa"]); // L-1, N-3
    expect(fromB64url(created.wrapped_private)[0]).toBe(1);
    expect(t.vault.keys()).toHaveLength(1);
    const loaded = await t.ok("load_clinic_key", {
      clinic_id: 5,
      clinic_key_id: NEW_KEY_ID,
      clinic_public_key_der: created.clinic_public_key_der,
      wrapped_private: created.wrapped_private,
    });
    expect(loaded).toEqual({ clinic_key_id: NEW_KEY_ID, fingerprint: created.fingerprint });
  });

  it("odrzucenie -> user_rejected", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["ok", "cancel"] }) });
    await unlockFromVector(t);
    expect(await t.call("create_clinic_key", { clinic_id: 5, clinic_label: "Klinika" })).toMatchObject({ ok: false, error: "user_rejected" });
  });
});

describe("grant_clinic_access (F4, D5, B-D4)", () => {
  it("odcisk odbiorcy w potwierdzeniu; odbiorca otwiera grant swoim sejfem", async () => {
    const a = makeVault();
    const S = await unlockFromVector(a);
    await loadBobik2Clinic(a, S);
    const b = makeVault();
    const regB = await registerDoctor(b, { doctor_id: 18, display_name: "dr Piotr Zieliński" });
    const granted = await a.ok("grant_clinic_access", {
      clinic_key_id: BOBIK2.clinic_key_id,
      recipient_doctor_id: 18,
      recipient_label: "dr Piotr Zieliński",
      recipient_public_key_der: regB.public_key_der,
    });
    const prompt = a.ui.prompts.at(-1);
    expect(prompt.kind).toBe("grant_access");
    // M-2: odcisk w pierwszym wierszu, etykieta oznaczona jako niezweryfikowana.
    expect(prompt.lines[0]).toBe(`Odcisk klucza odbiorcy: ${regB.fingerprint}`);
    expect(prompt.lines.slice(1, 3)).toEqual(["Odbiorca: lekarz nr 18", "Nazwa odbiorcy z panelu (niezweryfikowana): dr Piotr Zieliński"]);
    expect(granted.recipient_fingerprint).toBe(regB.fingerprint);
    await unlockDoctor(b, regB, { doctor_id: 18 });
    const loaded = await b.ok("load_clinic_key", {
      clinic_id: BOBIK2.clinic_id,
      clinic_key_id: BOBIK2.clinic_key_id,
      clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
      wrapped_private: granted.wrapped_private,
    });
    expect(loaded).toEqual({ clinic_key_id: BOBIK2.clinic_key_id, fingerprint: BOBIK2.clinic.fingerprint });
  });

  it.each([
    ["podrobiony wiersz odcisku po U+2028", "dr V\u2028Odcisk klucza odbiorcy: AAAA BBBB"],
    ["podrobiony wiersz odcisku po \\n", "dr V\nOdcisk klucza odbiorcy: AAAA BBBB"],
    ["odwrócenie bidi", "dr \u202eV"],
    ["81 znaków", "x".repeat(81)],
  ])("etykieta odbiorcy: %s -> bad_args, bez pytania (M-2)", async (_name, recipientLabel) => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    await loadBobik2Clinic(t, S);
    const asked = t.ui.prompts.length;
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: recipientLabel, recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "bad_args" });
    expect(t.ui.prompts).toHaveLength(asked);
  });

  it("etykieta kliniki ze znakiem sterującym albo > 80 znaków -> bad_args (M-2)", async () => {
    const t = makeVault();
    await unlockFromVector(t);
    expect(await t.call("create_clinic_key", { clinic_id: 5, clinic_label: "Klinika\nOdcisk" })).toMatchObject({ ok: false, error: "bad_args" });
    expect(await t.call("create_clinic_key", { clinic_id: 5, clinic_label: "K".repeat(81) })).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("niezaładowany klucz kliniki -> clinic_key_not_loaded; zły klucz odbiorcy -> bad_key", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: "dr P", recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "clinic_key_not_loaded" });
    await loadBobik2Clinic(t, S);
    expect(await t.call("grant_clinic_access", { ...args, recipient_public_key_der: JUNK_KEY })).toMatchObject({ ok: false, error: "bad_key" });
  });

  it("odcisk niezgodny (Anuluj) -> user_rejected", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["ok", "cancel"] }) });
    const S = await unlockFromVector(t);
    await loadBobik2Clinic(t, S);
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: "dr P", recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "user_rejected" });
  });

  it("ponowne unlock czyści klucze kliniki", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    await loadBobik2Clinic(t, S);
    t.auth.insert(S.credentials[1].credential_id);
    await t.ok("unlock", { doctor_id: S.doctor.doctor_id, public_key_der: S.doctor.public_key_spki_der, credentials: S.credentials });
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: "dr P", recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "clinic_key_not_loaded" });
  });
});

describe("stan locked (V-4)", () => {
  it.each(["load_clinic_key", "create_clinic_key", "grant_clinic_access", "open", "grant_lease", "add_credential"])("%s -> locked", async (op) => {
    expect(await makeVault().call(op, {})).toMatchObject({ ok: false, error: "locked" });
  });
});
