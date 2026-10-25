import { describe, expect, it, vi } from "vitest";
import { fromB64url, toB64url } from "../../src/b64.js";
import { VERSION } from "../../src/config.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { fakeUi } from "../helpers/fake-ui.js";
import { fakeAuthenticators } from "../helpers/fake-webauthn.js";
import { makeVault, registerDoctor, unlockDoctor } from "../helpers/vault.js";

const REG = { doctor_id: 17, display_name: "dr Anna Nowak" };
const SALT = "A".repeat(43); // 32 B
const WRAP = "A".repeat(40); // 30 B

describe("koperta i walidacja (V-2)", () => {
  it("hello", async () => {
    const t = makeVault();
    expect(await t.call("hello")).toEqual({ v: 1, id: "t1", ok: true, result: { version: VERSION, revoked: false, browser_ok: true, prf: true, state: "locked" } });
  });

  it.each([
    [null, "bad_message"],
    [{ v: 2, id: "a", op: "hello" }, "bad_version"],
    [{ v: 1, id: "x".repeat(65), op: "hello" }, "bad_id"],
    [{ v: 1, id: "a" }, "bad_op"],
  ])("%j -> %s, id null", async (data, code) => {
    expect(await makeVault().vault.respond(data)).toEqual({ v: 1, id: null, ok: false, error: code });
  });

  it.each(["rm_rf", "toString", "__proto__", "constructor"])("operacja %s -> unknown_op", async (op) => {
    expect(await makeVault().call(op)).toMatchObject({ ok: false, error: "unknown_op" });
  });

  it.each([
    ["register", { display_name: "dr A" }],
    ["register", { doctor_id: 0, display_name: "dr A" }],
    ["register", { doctor_id: "17", display_name: "dr A" }],
    ["register", { doctor_id: 17, display_name: "" }],
    ["register", { doctor_id: 17, display_name: "dr A\u2028Lekarz: dr B" }],
    ["register", { doctor_id: 17, display_name: "d".repeat(81) }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [] }],
    ["unlock", { doctor_id: 17, public_key_der: "A+AA", credentials: [{ credential_id: "AQ", prf_salt: SALT, wrapped_private: WRAP }] }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [{ credential_id: "AQ", prf_salt: "AQ", wrapped_private: WRAP }] }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [{ credential_id: "AQ", prf_salt: SALT, wrapped_private: "AQ" }] }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [{ credential_id: "", prf_salt: SALT, wrapped_private: WRAP }] }],
  ])("%s %j -> bad_args", async (op, args) => {
    expect(await makeVault().call(op, args)).toMatchObject({ ok: false, error: "bad_args" });
  });
});

describe("register (V-8, rozstrzygnięcie 16, P1)", () => {
  it("dwa klucze, UV required, excludeCredentials; wynik do POST doctor-key/; sejf zostaje zablokowany", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const [c1, c2] = t.auth.calls.create;
    expect(c1.authenticatorSelection.userVerification).toBe("required");
    expect(c1.excludeCredentials).toEqual([]);
    expect(c2.excludeCredentials.map((d) => new Uint8Array(d.id))).toEqual([fromB64url(reg.credentials[0].credential_id)]);
    expect(t.auth.calls.get).toHaveLength(0);
    expect(reg.credentials).toHaveLength(2);
    expect(reg.credentials[0].prf_salt).not.toBe(reg.credentials[1].prf_salt);
    for (const c of reg.credentials) {
      expect(fromB64url(c.prf_salt)).toHaveLength(32);
      expect(fromB64url(c.wrapped_private)[0]).toBe(1);
    }
    expect(reg.fingerprint).toMatch(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
    expect((await importP256Public(fromB64url(reg.public_key_der))).algorithm.namedCurve).toBe("P-256");
    expect(t.ui.prompts.map((p) => p.kind)).toEqual(["register_key", "register_key"]);
    expect((await t.call("hello")).result.state).toBe("locked");
  });

  it("klucz bez PRF przy create() -> drugie dotknięcie (get z UV) dla każdego klucza", async () => {
    const t = makeVault({ auth: fakeAuthenticators({ prfAtCreate: false }) });
    const reg = await registerDoctor(t);
    expect(t.ui.prompts.map((p) => p.kind)).toEqual(["register_key", "second_touch", "register_key", "second_touch"]);
    expect(t.auth.calls.get).toHaveLength(2);
    expect(t.auth.calls.get[0].userVerification).toBe("required");
    expect(await unlockDoctor(t, reg)).toEqual({ fingerprint: reg.fingerprint });
  });

  it("ten sam YubiKey jako drugi -> already_registered, a sejf przyjmuje kolejną operację", async () => {
    const t = makeVault();
    t.ui.onAsk = (_prompt, index) => {
      if (index === 0) t.auth.insertNew(); // przy drugim pytaniu zostaje włożony pierwszy klucz
    };
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "already_registered" });
    t.ui.onAsk = null;
    expect((await registerDoctor(t)).credentials).toHaveLength(2);
  });

  it("lekarz anuluje -> user_rejected, WebAuthn nie wołane", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["cancel"] }) });
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "user_rejected" });
    expect(t.auth.calls.create).toHaveLength(0);
  });

  it("brak klucza w porcie -> not_allowed", async () => {
    expect(await makeVault().call("register", REG)).toMatchObject({ ok: false, error: "not_allowed" });
  });
});

describe("unlock", () => {
  it("jedno get() z evalByCredential; drugi klucz; odcisk = odcisk z rejestracji; klucz nieeksportowalny", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    expect(await unlockDoctor(t, reg, { index: 0 })).toEqual({ fingerprint: reg.fingerprint });
    const get = t.auth.calls.get.at(-1);
    expect(get.userVerification).toBe("required");
    expect(Object.keys(get.extensions.prf.evalByCredential).sort()).toEqual(reg.credentials.map((c) => c.credential_id).sort());
    expect((await t.call("hello")).result.state).toBe("unlocked");
    expect(t.vault.keys()).toHaveLength(1);
    expect(t.vault.keys().every((k) => k.extractable === false)).toBe(true);
    expect(t.vault.view()).toMatchObject({ state: "unlocked", doctorId: 17, fingerprint: reg.fingerprint, counters: { interviews: 0, stc: 0 } }); // M-5
    expect(t.events).toEqual([]);
  });

  it("poświadczenia prosto z GET state/ (nadmiarowe id, label, created_at) są przyjmowane (P5)", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const fromState = reg.credentials.map((c, i) => ({ id: i + 1, label: "", created_at: "2026-10-25T10:00:00+00:00", ...c }));
    t.auth.insert(reg.credentials[1].credential_id);
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: fromState })).toMatchObject({ ok: true });
  });

  it("podmieniony klucz publiczny lekarza -> unwrap_failed, sejf zablokowany (B-D4)", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const other = await registerDoctor(t, { doctor_id: 18 });
    t.auth.insert(reg.credentials[1].credential_id);
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: other.public_key_der, credentials: reg.credentials })).toMatchObject({ ok: false, error: "unwrap_failed" });
    expect((await t.call("hello")).result.state).toBe("locked");
  });

  it("inny doctor_id -> unwrap_failed", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await expect(unlockDoctor(t, reg, { doctor_id: 18 })).rejects.toThrow("unlock: unwrap_failed");
  });

  it("klucz publiczny spoza P-256 -> bad_key", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    t.auth.insert(reg.credentials[1].credential_id);
    const junk = toB64url(new Uint8Array(91).fill(7));
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: junk, credentials: reg.credentials })).toMatchObject({ ok: false, error: "bad_key" });
  });

  it("włożony klucz spoza listy -> not_allowed", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    t.auth.insertNew();
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials })).toMatchObject({ ok: false, error: "not_allowed" });
  });
});

describe("add_credential (F3, B-D5)", () => {
  it("istniejący klucz -> nowy klucz; nowym wrapem da się odblokować", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await unlockDoctor(t, reg);
    t.ui.onAsk = (prompt) => {
      if (prompt.kind === "add_existing") t.auth.insert(reg.credentials[0].credential_id);
      if (prompt.kind === "add_new") t.auth.insertNew();
    };
    const { credential } = await t.ok("add_credential", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials });
    t.ui.onAsk = null;
    expect(t.ui.prompts.slice(-2).map((p) => p.kind)).toEqual(["add_existing", "add_new"]);
    expect(t.auth.calls.create.at(-1).excludeCredentials).toHaveLength(2);
    expect(fromB64url(credential.wrapped_private)[0]).toBe(1);
    await t.ok("lock");
    t.auth.insert(credential.credential_id);
    const all = [...reg.credentials, credential];
    expect(await t.ok("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: all })).toEqual({ fingerprint: reg.fingerprint });
  });

  it("lekarz inny niż odblokowany -> bad_args", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await unlockDoctor(t, reg);
    expect(await t.call("add_credential", { doctor_id: 18, public_key_der: reg.public_key_der, credentials: reg.credentials })).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("w stanie locked -> locked (przed walidacją argumentów)", async () => {
    expect(await makeVault().call("add_credential", {})).toMatchObject({ ok: false, error: "locked" });
  });
});

describe("stany (V-4)", () => {
  it.each([[{ revoked: [VERSION] }], [null], [{}], [{ revoked: VERSION }]])("lista unieważnień %j -> refusing/revoked", async (doc) => {
    const t = makeVault({ revoked: doc });
    expect((await t.call("hello")).result).toMatchObject({ revoked: true, state: "refusing" });
    for (const op of ["register", "unlock", "lock", "add_credential"]) {
      expect(await t.call(op, {})).toMatchObject({ ok: false, error: "revoked" });
    }
    expect(t.ui.views.at(-1)).toMatchObject({ state: "refusing", refusal: "revoked" });
  });

  it("przeglądarka zablokowana -> refusing/browser_blocked (D13)", async () => {
    const t = makeVault({ browserOk: false });
    expect((await t.call("hello")).result).toMatchObject({ browser_ok: false, revoked: false, state: "refusing" });
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "browser_blocked" });
    expect(await t.call("unlock", {})).toMatchObject({ ok: false, error: "browser_blocked" });
  });

  it("żądanie przed pobraniem revoked.json czeka na listę zamiast dostać locked", async () => {
    let resolve;
    const ready = new Promise((r) => { resolve = r; });
    const t = makeVault({ ready });
    let done = false;
    const pending = t.call("hello").then((res) => { done = true; return res; });
    await new Promise((r) => setTimeout(r, 20));
    expect(done).toBe(false);
    resolve({ revoked: [] });
    expect((await pending).result.state).toBe("locked");
  });

  it("lock w stanie locked: {} bez zdarzenia", async () => {
    const t = makeVault();
    expect(await t.ok("lock")).toEqual({});
    expect(t.events).toEqual([]);
  });

  it("lock po odblokowaniu: klucze usunięte, zdarzenie locked/user; vault.lock() (przycisk) tak samo", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await unlockDoctor(t, reg);
    expect(await t.ok("lock")).toEqual({});
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "user" }]);
    expect(t.vault.keys()).toEqual([]);
    expect((await t.call("hello")).result.state).toBe("locked");
    await unlockDoctor(t, reg);
    t.vault.lock();
    expect(t.events.at(-1)).toEqual({ v: 1, event: "locked", reason: "user" });
  });
});

describe("busy, blokada w trakcie operacji, limit czasu (P3, P4, Review Focus 1)", () => {
  it("druga operacja interaktywna -> busy; hello działa; lock przerywa pierwszą kodem locked", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["hang"] }) });
    const first = t.call("register", REG);
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "busy" });
    expect(await t.call("hello")).toMatchObject({ ok: true });
    await t.ok("lock");
    expect(await first).toMatchObject({ ok: false, error: "locked" });
    expect((await registerDoctor(t)).credentials).toHaveLength(2);
  });

  it("unlock z wiszącym potwierdzeniem + blokada -> locked i brak kluczy", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    t.ui.answers.push("hang");
    t.auth.insert(reg.credentials[0].credential_id);
    const pending = t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials });
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    t.vault.lock();
    expect(await pending).toMatchObject({ ok: false, error: "locked" });
    expect((await t.call("hello")).result.state).toBe("locked");
    expect(t.vault.keys()).toEqual([]);
  });

  // Przegląd 5–8, L3: register nie używa kluczy sesji, ale operacja sprzed blokady kończy się locked
  // (P3). Atrapa ignoruje AbortSignal, więc sprawdza kontrolę epoki, a nie przerwanie WebAuthn.
  it("register: blokada w trakcie create() drugiego klucza -> locked, bez public_key_der", async () => {
    const t = makeVault();
    const create = t.auth.credentials.create;
    let release;
    const gate = new Promise((r) => { release = r; });
    let calls = 0;
    t.auth.credentials.create = async (opts) => {
      calls += 1;
      if (calls === 2) await gate;
      return create(opts);
    };
    t.ui.onAsk = (prompt) => {
      if (prompt.kind === "register_key") t.auth.insertNew();
    };
    const pending = t.call("register", REG);
    await vi.waitFor(() => expect(calls).toBe(2));
    t.vault.lock();
    release();
    const res = await pending;
    expect(res).toEqual({ v: 1, id: "t1", ok: false, error: "locked" });
  });

  // Przegląd 5–8, L2: natywne okno WebAuthn nie kończy się samo przy blokadzie, więc trzymało busy.
  // Atrapa: wywołanie wisi, dopóki sygnał go nie przerwie (jak przeglądarka: AbortError).
  function hangUntilAborted(seen) {
    return (options) =>
      new Promise((_resolve, reject) => {
        seen.push(options.signal);
        options.signal?.addEventListener("abort", () => reject(new DOMException("przerwane", "AbortError")));
      });
  }

  it("register: blokada przerywa create() przez AbortSignal -> locked; busy zwolnione, nowe pytanie się nie pojawia", async () => {
    const t = makeVault();
    const create = t.auth.credentials.create;
    const signals = [];
    t.auth.credentials.create = hangUntilAborted(signals);
    t.auth.insertNew();
    const pending = t.call("register", REG);
    await vi.waitFor(() => expect(signals).toHaveLength(1));
    expect(signals[0]).toBeInstanceOf(AbortSignal);
    t.vault.lock();
    expect(await pending).toMatchObject({ ok: false, error: "locked" });
    expect(signals[0].aborted).toBe(true);
    expect(t.ui.prompts.map((p) => p.kind)).toEqual(["register_key"]);
    t.auth.credentials.create = create;
    expect((await registerDoctor(t)).credentials).toHaveLength(2);
  });

  it("unlock: blokada przerywa get() -> locked; kolejna operacja interaktywna nie dostaje busy", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const get = t.auth.credentials.get;
    const signals = [];
    t.auth.credentials.get = hangUntilAborted(signals);
    const pending = t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials });
    await vi.waitFor(() => expect(signals).toHaveLength(1));
    t.vault.lock();
    expect(await pending).toMatchObject({ ok: false, error: "locked" });
    expect(signals[0].aborted).toBe(true);
    t.auth.credentials.get = get;
    expect(await unlockDoctor(t, reg)).toEqual({ fingerprint: reg.fingerprint });
  });

  it("AbortError bez blokady (np. inne okno WebAuthn) -> webauthn_failed, nie locked", async () => {
    const t = makeVault();
    t.auth.credentials.create = async () => {
      throw new DOMException("przerwane", "AbortError");
    };
    t.auth.insertNew();
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "webauthn_failed" });
  });

  it("potwierdzenie bez odpowiedzi przez 120 s -> user_rejected", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["hang"] }) });
    const pending = t.call("register", REG);
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    expect(t.timers.pending.size).toBe(1);
    t.timers.fireAll();
    expect(await pending).toMatchObject({ ok: false, error: "user_rejected" });
  });

  it("nieprzewidziany wyjątek -> internal, w konsoli tylko typ", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const auth = fakeAuthenticators();
    auth.credentials.create = async () => ({ broken: true });
    expect(await makeVault({ auth }).call("register", REG)).toMatchObject({ ok: false, error: "internal" });
    expect(spy).toHaveBeenCalledWith("sejf: nieprzewidziany błąd", "TypeError");
    spy.mockRestore();
  });
});
