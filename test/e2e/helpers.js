// Pomocnicy E2E: atrapa panelu, wywołania sejfu, przyciski w ramce, wirtualne authenticatory CDP.
import { expect } from "@playwright/test";
import { PANEL, VAULT, VAULT_PATH } from "../../playwright.config.js";
import { toB64url } from "../../src/b64.js";
import { random, sha256Hex, utf8 } from "../../src/bytes.js";
import { sealClinicGrant } from "../../src/crypto/clinic.js";
import { dekInfo } from "../../src/crypto/context.js";
import { hpkeSeal } from "../../src/crypto/hpke.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { BOBIK2, b } from "../helpers/vectors.js";

export const AUTH_OPTS = {
  protocol: "ctap2",
  ctap2Version: "ctap2_1",
  transport: "usb",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  hasPrf: true,
  automaticPresenceSimulation: true,
};

export async function openPanel(page, { base = PANEL, noAllow = false } = {}) {
  const query = new URLSearchParams({ vault_path: VAULT_PATH });
  if (noAllow) query.set("no_allow", "1");
  await page.goto(`${base}/?${query}`);
  await page.evaluate(() => window.vaultReady);
}

export const call = (page, op, args = {}, timeoutMs = 120_000) =>
  page.evaluate(([o, a, t]) => window.vaultCall(o, a, t), [op, args, timeoutMs]);

export const vaultFrame = (page) => page.frameLocator("#vault");
export const button = (page, name) => vaultFrame(page).getByRole("button", { name, exact: true });
export const clickInVault = (page, name) => button(page, name).click();

// Ramka sejfu jako Frame (do evaluate w originie sejfu).
export function vaultFrameHandle(page) {
  const frame = page.frames().find((f) => f.url().startsWith(VAULT));
  expect(frame, "ramka sejfu").toBeTruthy();
  return frame;
}

// Wirtualne YubiKeye na sesji CDP strony — obsługują też żądania z ramki sejfu (spike 4).
export async function authenticators(context, page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  return {
    insert: async () => (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: AUTH_OPTS })).authenticatorId,
    remove: (authenticatorId) => cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }),
  };
}

// Rejestracja jak u lekarza: klucz 1 → (drugie dotknięcie) → wyjęcie, klucz 2 → (drugie dotknięcie).
export async function register(page, auth, { doctorId, displayName, secondTouch = false }) {
  const first = await auth.insert();
  const pending = call(page, "register", { doctor_id: doctorId, display_name: displayName });
  await clickInVault(page, "Zarejestruj klucz 1");
  if (secondTouch) await clickInVault(page, "Dotknij ponownie");
  await expect(button(page, "Zarejestruj klucz 2")).toBeVisible();
  await auth.remove(first);
  await auth.insert();
  await clickInVault(page, "Zarejestruj klucz 2");
  if (secondTouch) await clickInVault(page, "Dotknij ponownie");
  const res = await pending;
  expect(res, JSON.stringify(res)).toMatchObject({ ok: true });
  return res.result;
}

// Odblokowanie kluczem, który jest włożony (po register: drugi).
export async function unlock(page, reg, doctorId) {
  const pending = call(page, "unlock", { doctor_id: doctorId, public_key_der: reg.public_key_der, credentials: reg.credentials });
  await clickInVault(page, "Odblokuj");
  const res = await pending;
  expect(res, JSON.stringify(res)).toMatchObject({ ok: true });
  return res.result;
}

// Grant F4 klucza kliniki z bobik2_v1.json dla świeżo zarejestrowanego lekarza — liczony w Node,
// tak jak zrobiłby to inny posiadacz klucza kliniki (grant_clinic_access); potem load_clinic_key.
export async function grantBobik2Clinic(page, reg, doctorId) {
  const doctorKey = await importP256Public(b(reg.public_key_der));
  const grant = await sealClinicGrant(doctorKey, {
    clinicId: BOBIK2.clinic_id,
    doctorId,
    clinicSpkiHex: await sha256Hex(b(BOBIK2.clinic.public_key_spki_der)),
    pkcs8: b(BOBIK2.clinic.private_key_pkcs8_der),
  });
  const res = await call(page, "load_clinic_key", {
    clinic_id: BOBIK2.clinic_id,
    clinic_key_id: BOBIK2.clinic_key_id,
    clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
    wrapped_private: toB64url(grant),
  });
  expect(res, JSON.stringify(res)).toMatchObject({ ok: true, result: { fingerprint: BOBIK2.clinic.fingerprint } });
}

// Wywiady pod kluczem kliniki z bobik2_v1.json, z losowym DEK — do testu limitu.
export async function fakeInterviews(n) {
  const pub = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  const out = [];
  for (let i = 0; i < n; i++) {
    const id = crypto.randomUUID();
    const wrap = await hpkeSeal(pub, utf8(dekInfo(id)), random(32));
    out.push({ interview_id: id, interview_key_id: crypto.randomUUID(), clinic_key_id: BOBIK2.clinic_key_id, clinic_wrap: toB64url(wrap) });
  }
  return out;
}

export const shiftClock = (page, ms) => vaultFrameHandle(page).evaluate((delta) => window.__bobikShiftClock(delta), ms);
