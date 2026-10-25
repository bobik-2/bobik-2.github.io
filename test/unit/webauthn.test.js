import { describe, expect, it, vi } from "vitest";
import { evaluatePrf, prfSupport, registerCredential } from "../../src/webauthn.js";
import { toB64url } from "../../src/b64.js";

const id1 = new Uint8Array([1, 1, 1]);
const id2 = new Uint8Array([2, 2, 2]);
const salt1 = new Uint8Array(32).fill(7);
const salt2 = new Uint8Array(32).fill(9);
const prfOut = new Uint8Array(32).fill(5);

const AAGUID = "ee882879-721c-4913-9775-3dfcce97072a";

// authenticatorData z attestedCredentialData: rpIdHash(32) flags(1) signCount(4) aaguid(16) ...
function authData(aaguidHex) {
  const d = new Uint8Array(37 + 16 + 2);
  d[32] = 0x41; // UP + AT
  d.set(Uint8Array.from(aaguidHex.replaceAll("-", "").match(/../g), (h) => parseInt(h, 16)), 37);
  return d.buffer;
}

function fakeCred(rawId, prf, { attachment = "cross-platform", transports = ["usb"], aaguid = AAGUID } = {}) {
  return {
    rawId: rawId.buffer,
    authenticatorAttachment: attachment,
    response: { getTransports: () => transports, getAuthenticatorData: () => authData(aaguid) },
    getClientExtensionResults: () => ({ prf }),
  };
}

describe("registerCredential", () => {
  const args = { rpId: "bobik-2.github.io", rpName: "Sejf", userId: new Uint8Array(16), userName: "l", displayName: "L", salt: salt1, excludeIds: [id2] };

  it("zwraca id, prf przy rejestracji i przekazuje sól + excludeCredentials", async () => {
    const credentials = { create: vi.fn(async () => fakeCred(id1, { enabled: true, results: { first: prfOut.buffer } })) };
    const res = await registerCredential(credentials, args);
    expect(res).toEqual({ credentialId: id1, prfEnabled: true, prfFirst: prfOut, aaguid: AAGUID, transports: ["usb"] });
    const pk = credentials.create.mock.calls[0][0].publicKey;
    expect(pk.authenticatorSelection.authenticatorAttachment).toBe("cross-platform");
    // Rozstrzygnięcie 6: PIN YubiKeya obowiązkowy — hmac-secret z UV i bez UV to różne sekrety.
    expect(pk.authenticatorSelection.userVerification).toBe("required");
    expect(pk.hints).toEqual(["security-key"]);
    expect(pk.rp.id).toBe("bobik-2.github.io");
    expect(pk.extensions.prf.eval.first).toBe(salt1);
    expect(pk.excludeCredentials).toEqual([{ type: "public-key", id: id2 }]);
    expect(pk.pubKeyCredParams).toContainEqual({ type: "public-key", alg: -7 });
  });

  it.each([
    ["platform (Touch ID / pęk kluczy iCloud)", { attachment: "platform", transports: ["internal"] }],
    ["telefon przez QR (hybrid)", { attachment: "cross-platform", transports: ["hybrid", "internal"] }],
    ["transport internal", { attachment: null, transports: ["internal"] }],
  ])("odrzuca klucz, który nie jest sprzętowym: %s", async (_label, opts) => {
    const credentials = { create: vi.fn(async () => fakeCred(id1, { enabled: true }, opts)) };
    await expect(registerCredential(credentials, args)).rejects.toMatchObject({ code: "not_security_key" });
  });

  it("AAGUID wyzerowany przez przeglądarkę -> null", async () => {
    const credentials = { create: vi.fn(async () => fakeCred(id1, { enabled: true }, { aaguid: "00000000-0000-0000-0000-000000000000" })) };
    expect(await registerCredential(credentials, args)).toMatchObject({ aaguid: null });
  });

  it("YubiKey bez hmac-secret-mc: enabled bez wyniku -> prfFirst null", async () => {
    const credentials = { create: vi.fn(async () => fakeCred(id1, { enabled: true })) };
    expect(await registerCredential(credentials, args)).toMatchObject({ prfEnabled: true, prfFirst: null });
  });

  it("brak PRF w ogóle -> kod no_prf", async () => {
    const credentials = { create: vi.fn(async () => fakeCred(id1, undefined)) };
    await expect(registerCredential(credentials, args)).rejects.toMatchObject({ code: "no_prf" });
  });

  it("anulowanie / timeout -> kod not_allowed", async () => {
    const credentials = { create: vi.fn(async () => { throw new DOMException("x", "NotAllowedError"); }) };
    await expect(registerCredential(credentials, args)).rejects.toMatchObject({ code: "not_allowed" });
  });

  it("ten sam YubiKey drugi raz -> kod already_registered", async () => {
    const credentials = { create: vi.fn(async () => { throw new DOMException("x", "InvalidStateError"); }) };
    await expect(registerCredential(credentials, args)).rejects.toMatchObject({ code: "already_registered" });
  });
});

describe("evaluatePrf", () => {
  const keys = [{ credentialId: id1, salt: salt1 }, { credentialId: id2, salt: salt2 }];

  it("jedno get() z evalByCredential; wynik wskazuje klucz po rawId", async () => {
    const credentials = { get: vi.fn(async () => fakeCred(id2, { results: { first: prfOut.buffer } })) };
    const res = await evaluatePrf(credentials, { rpId: "bobik-2.github.io", keys });
    expect(res).toEqual({ index: 1, prfFirst: prfOut });
    const pk = credentials.get.mock.calls[0][0].publicKey;
    expect(pk.hints).toEqual(["security-key"]);
    expect(pk.userVerification).toBe("required");
    expect(pk.allowCredentials).toEqual([{ type: "public-key", id: id1 }, { type: "public-key", id: id2 }]);
    expect(pk.extensions.prf.evalByCredential).toEqual({ [toB64url(id1)]: { first: salt1 }, [toB64url(id2)]: { first: salt2 } });
  });

  it("odpowiedź klucza spoza listy -> unknown_credential", async () => {
    const credentials = { get: vi.fn(async () => fakeCred(new Uint8Array([3]), { results: { first: prfOut.buffer } })) };
    await expect(evaluatePrf(credentials, { rpId: "x", keys })).rejects.toMatchObject({ code: "unknown_credential" });
  });

  it("odpowiedź authenticatora platformowego -> not_security_key", async () => {
    const credentials = { get: vi.fn(async () => fakeCred(id1, { results: { first: prfOut.buffer } }, { attachment: "platform" })) };
    await expect(evaluatePrf(credentials, { rpId: "x", keys })).rejects.toMatchObject({ code: "not_security_key" });
  });

  it("brak wyniku PRF -> no_prf", async () => {
    const credentials = { get: vi.fn(async () => fakeCred(id1, {})) };
    await expect(evaluatePrf(credentials, { rpId: "x", keys })).rejects.toMatchObject({ code: "no_prf" });
  });

  it("pusta lista kluczy -> no_keys (bez wołania przeglądarki)", async () => {
    const credentials = { get: vi.fn() };
    await expect(evaluatePrf(credentials, { rpId: "x", keys: [] })).rejects.toMatchObject({ code: "no_keys" });
    expect(credentials.get).not.toHaveBeenCalled();
  });
});

describe("prfSupport", () => {
  it("getClientCapabilities -> true/false", async () => {
    expect(await prfSupport({ PublicKeyCredential: { getClientCapabilities: async () => ({ "extension:prf": true }) } })).toBe(true);
    expect(await prfSupport({ PublicKeyCredential: { getClientCapabilities: async () => ({}) } })).toBe(false);
  });
  it("brak API -> null (nie wiadomo)", async () => {
    expect(await prfSupport({ PublicKeyCredential: function () {} })).toBe(null);
    expect(await prfSupport({})).toBe(false);
  });
});
