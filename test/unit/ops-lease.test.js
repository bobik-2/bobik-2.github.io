import { describe, expect, it, vi } from "vitest";
import { toB64url } from "../../src/b64.js";
import { fakeUi } from "../helpers/fake-ui.js";
import { BOBIK2, b, bobik2LeaseArgs } from "../helpers/vectors.js";
import { loadBobik2Clinic, makeVault, unlockFromVector } from "../helpers/vault.js";

async function ready(opts) {
  const t = makeVault(opts);
  const S = await unlockFromVector(t);
  await loadBobik2Clinic(t, S);
  return t;
}

async function openWithLeaseKey(wrapped) {
  const priv = await crypto.subtle.importKey("pkcs8", b(BOBIK2.rsa_lease_key.private_key_pkcs8_der), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  return toB64url(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b(wrapped))));
}

async function rsa2048Spki() {
  const k = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
  return toB64url(new Uint8Array(await crypto.subtle.exportKey("spki", k.publicKey)));
}

describe("grant_lease (F6, rozstrzygnięcie 2)", () => {
  it("dopisek: lekarz widzi wywiad, rodzaj i czas; DEK pod kluczem dzierżawy; liczy się raz jako otwarcie wywiadu", async () => {
    const t = await ready();
    const res = await t.ok("grant_lease", bobik2LeaseArgs());
    const lines = t.ui.prompts.at(-1).lines.join("\n");
    expect(t.ui.prompts.at(-1).kind).toBe("grant_lease");
    expect(lines).toContain("BOB-0001");
    expect(lines).toContain("7 dni");
    expect(b(res.rsa_wrapped_dek)).toHaveLength(384);
    expect(await openWithLeaseKey(res.rsa_wrapped_dek)).toBe(BOBIK2.dek);
    expect(t.vault.view().counters.interviews).toBe(1);
    await t.ok("grant_lease", bobik2LeaseArgs());
    expect(t.vault.view().counters.interviews).toBe(1);
  });

  it.each([
    [{ kind: "repair", session_seq: 2 }, "sesji 2"],
    [{ kind: "repair", agent_run_id: 9 }, "przebiegu agenta 9"],
  ])("naprawa %j", async (over, text) => {
    const t = await ready();
    await t.ok("grant_lease", bobik2LeaseArgs(over));
    const lines = t.ui.prompts.at(-1).lines.join("\n");
    expect(lines).toContain(text);
    expect(lines).toContain("1 h");
  });

  it.each([
    ["dopisek z session_seq", { session_seq: 1 }],
    ["naprawa bez celu", { kind: "repair" }],
    ["naprawa z sesją i przebiegiem", { kind: "repair", session_seq: 1, agent_run_id: 2 }],
    ["brak klucza session_seq", { session_seq: undefined }],
    ["nieznany rodzaj", { kind: "interview" }],
    ["pusty study_code", { study_code: "" }],
    ["zły interview_id", { interview_id: "42" }],
  ])("%s -> bad_args", async (_name, over) => {
    const t = await ready();
    expect(await t.call("grant_lease", bobik2LeaseArgs(over))).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("klucz dzierżawy RSA-2048 albo EC -> bad_lease_key", async () => {
    const t = await ready();
    expect(await t.call("grant_lease", bobik2LeaseArgs({ lease_public_key_der: await rsa2048Spki() }))).toMatchObject({ ok: false, error: "bad_lease_key" });
    expect(await t.call("grant_lease", bobik2LeaseArgs({ lease_public_key_der: BOBIK2.clinic.public_key_spki_der }))).toMatchObject({ ok: false, error: "bad_lease_key" });
  });

  it("niezaładowany klucz kliniki -> clinic_key_not_loaded", async () => {
    const t = await ready();
    expect(await t.call("grant_lease", bobik2LeaseArgs({ clinic_key_id: "00000000-0000-4000-8000-000000000001" }))).toMatchObject({ ok: false, error: "clinic_key_not_loaded" });
  });

  it("odrzucenie -> user_rejected, licznik bez zmian", async () => {
    const t = await ready({ ui: fakeUi({ answers: ["ok", "cancel"] }) });
    expect(await t.call("grant_lease", bobik2LeaseArgs())).toMatchObject({ ok: false, error: "user_rejected" });
    expect(t.vault.view().counters.interviews).toBe(0);
  });

  it("blokada przy wiszącym potwierdzeniu -> locked, bez rsa_wrapped_dek (Review Focus 1)", async () => {
    const t = await ready({ ui: fakeUi({ answers: ["ok", "hang"] }) });
    const pending = t.call("grant_lease", bobik2LeaseArgs());
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    t.vault.lock();
    expect(await pending).toEqual({ v: 1, id: expect.any(String), ok: false, error: "locked" });
  });
});
