import { expect, test } from "@playwright/test";
import { toB64url } from "../../src/b64.js";
import { BOBIK2, b, bobik2ExpectedValues, bobik2LeaseArgs, bobik2OpenRequest } from "../helpers/vectors.js";
import { authenticators, call, clickInVault, grantBobik2Clinic, openPanel, register, unlock, vaultFrame, vaultFrameHandle } from "./helpers.js";
import { stripPrfAtCreate } from "./shims.js";

test.skip(({ browserName }) => browserName !== "chromium", "wirtualne authenticatory tylko przez CDP (Chromium) — B-R9");

test("P-1: rejestracja, odblokowanie, klucz kliniki, nadanie dostępu, odczyt, dzierżawa, blokada", async ({ page, context, browser }) => {
  test.setTimeout(120_000);
  const authA = await authenticators(context, page);
  await openPanel(page);
  const regA = await register(page, authA, { doctorId: 17, displayName: "dr Anna Nowak" });
  expect(await unlock(page, regA, 17)).toEqual({ fingerprint: regA.fingerprint });
  await expect(vaultFrame(page).locator("#fingerprint")).toContainText(regA.fingerprint);

  // create_clinic_key → load_clinic_key; etykieta z HTML-em pokazana dosłownie (Review Focus 2).
  const label = '<img src=x onerror="window.pwned=1">Klinika Testowa';
  const creating = call(page, "create_clinic_key", { clinic_id: 5, clinic_label: label });
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText(label);
  await expect(vaultFrame(page).locator("#prompt img")).toHaveCount(0);
  await clickInVault(page, "Załóż klucz");
  const created = await creating;
  expect(created).toMatchObject({ ok: true });
  const clinicKeyId = crypto.randomUUID();
  const loaded = await call(page, "load_clinic_key", {
    clinic_id: 5,
    clinic_key_id: clinicKeyId,
    clinic_public_key_der: created.result.clinic_public_key_der,
    wrapped_private: created.result.wrapped_private,
  });
  expect(loaded).toMatchObject({ ok: true, result: { clinic_key_id: clinicKeyId, fingerprint: created.result.fingerprint } });

  // Drugi lekarz w osobnym kontekście; nadający widzi w sejfie jego odcisk.
  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  const authB = await authenticators(contextB, pageB);
  await openPanel(pageB);
  const regB = await register(pageB, authB, { doctorId: 18, displayName: "dr Piotr Zieliński" });
  // recipient_label z HTML-em też trafia do DOM wyłącznie jako tekst (przegląd 9–10, L-2).
  const recipientLabel = '<img src=x onerror="window.pwned=1">dr Piotr Zieliński';
  const granting = call(page, "grant_clinic_access", {
    clinic_key_id: clinicKeyId,
    recipient_doctor_id: 18,
    recipient_label: recipientLabel,
    recipient_public_key_der: regB.public_key_der,
  });
  await expect(vaultFrame(page).locator("#prompt-lines p").first()).toHaveText(`Odcisk klucza odbiorcy: ${regB.fingerprint}`);
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText(recipientLabel);
  await expect(vaultFrame(page).locator("#prompt img")).toHaveCount(0);
  await clickInVault(page, "Odcisk zgodny — nadaj dostęp");
  const granted = await granting;
  expect(granted).toMatchObject({ ok: true, result: { recipient_fingerprint: regB.fingerprint } });
  await unlock(pageB, regB, 18);
  const loadedB = await call(pageB, "load_clinic_key", {
    clinic_id: 5,
    clinic_key_id: clinicKeyId,
    clinic_public_key_der: created.result.clinic_public_key_der,
    wrapped_private: granted.result.wrapped_private,
  });
  expect(loadedB).toMatchObject({ ok: true, result: { fingerprint: created.result.fingerprint } });
  await contextB.close();

  // open danych z bobik2_v1.json (klucz kliniki z wektora, grant dla lekarza A).
  await grantBobik2Clinic(page, regA, 17);
  expect(await call(page, "open", bobik2OpenRequest())).toMatchObject({ ok: true, result: { values: bobik2ExpectedValues() } });
  await expect(vaultFrame(page).locator("#counter")).toContainText("Wywiady: 1/50 · wartości kliniki: 3/500"); // 2 pola STC + 1 przypadek negatywny

  // grant_lease: lekarz widzi wywiad, rodzaj i czas; DEK otwiera klucz dzierżawy.
  // study_code z HTML-em: tekst, nie element; pierwszy wiersz to UUID wywiadu (L-1, L-2).
  const studyCode = '<img src=x onerror="window.pwned=1">BOB-0001';
  const leasing = call(page, "grant_lease", bobik2LeaseArgs({ study_code: studyCode }));
  await expect(vaultFrame(page).locator("#prompt-lines p").first()).toHaveText(`Wywiad: ${BOBIK2.interview_id}`);
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText(`Kod wywiadu z panelu: ${studyCode}`);
  await expect(vaultFrame(page).locator("#prompt img")).toHaveCount(0);
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText("7 dni");
  await clickInVault(page, "Zatwierdź");
  const leased = await leasing;
  expect(leased).toMatchObject({ ok: true });
  const priv = await crypto.subtle.importKey("pkcs8", b(BOBIK2.rsa_lease_key.private_key_pkcs8_der), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  const dek = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b(leased.result.rsa_wrapped_dek)));
  expect(toB64url(dek)).toBe(BOBIK2.dek);

  // lock przyciskiem w sejfie → zdarzenie do panelu, klucze znikają.
  expect(await page.evaluate(() => window.vaultEvents)).toEqual([]);
  await clickInVault(page, "Zablokuj");
  await expect.poll(() => page.evaluate(() => window.vaultEvents)).toEqual([{ v: 1, event: "locked", reason: "user" }]);
  await expect(vaultFrame(page).locator("#status")).toHaveText("Sejf zablokowany");
  expect(await call(page, "open", bobik2OpenRequest())).toMatchObject({ ok: false, error: "locked" });
  // Uzupełniająco: CSP script-src 'self' zablokowałaby inline onerror nawet przy innerHTML, więc
  // dowodem braku sinka są asercje `#prompt img` = 0 powyżej, nie ta.
  expect(await vaultFrameHandle(page).evaluate(() => window.pwned)).toBeUndefined();
});

test("P-2: klucz bez PRF przy create() — drugie dotknięcie każdego klucza, potem unlock", async ({ page, context }) => {
  test.setTimeout(60_000);
  await context.addInitScript(stripPrfAtCreate);
  const auth = await authenticators(context, page);
  await openPanel(page);
  const reg = await register(page, auth, { doctorId: 17, displayName: "dr Anna Nowak", secondTouch: true });
  expect(await unlock(page, reg, 17)).toEqual({ fingerprint: reg.fingerprint });
});
