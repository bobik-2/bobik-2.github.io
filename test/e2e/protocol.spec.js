import { expect, test } from "@playwright/test";
import { FOREIGN_PANEL, VAULT, VAULT_PATH } from "../../playwright.config.js";
import { VERSION } from "../../src/config.js";
import { call, openPanel, vaultFrame, vaultFrameHandle } from "./helpers.js";

test("hello: wersja, stan, przeglądarka (moduły i wendorowane HPKE ładują się pod CSP)", async ({ page, browserName }) => {
  await openPanel(page);
  const res = await call(page, "hello");
  const blocked = browserName === "webkit";
  expect(res).toMatchObject({ v: 1, ok: true, result: { version: VERSION, revoked: false, browser_ok: !blocked, state: blocked ? "refusing" : "locked" } });
  expect([true, false, null]).toContain(res.result.prf);
});

test("P-4 / P-3: panel spoza listy originów nie dostaje żadnej odpowiedzi", async ({ page }) => {
  await openPanel(page, { base: FOREIGN_PANEL });
  expect(await call(page, "hello", {}, 2_000)).toEqual({ timeout: true });
});

test("P-4: stan locked odrzuca operacje wymagające odblokowania", async ({ page, browserName }) => {
  test.skip(browserName === "webkit", "WebKit jest w stanie refusing (P-5)");
  await openPanel(page);
  expect(await call(page, "open", { interviews: [], items: [] })).toMatchObject({ ok: false, error: "locked" });
  expect(await call(page, "lock")).toMatchObject({ ok: true, result: {} });
  await expect(vaultFrame(page).locator("#status")).toHaveText("Sejf zablokowany");
});

test("P-5: WebKit — register i unlock kończą się browser_blocked, ekran blokady", async ({ page, browserName }) => {
  test.skip(browserName !== "webkit", "blokada Safari dotyczy wyłącznie WebKit (D13)");
  await openPanel(page);
  expect(await call(page, "register", { doctor_id: 17, display_name: "dr Anna Nowak" })).toMatchObject({ ok: false, error: "browser_blocked" });
  expect(await call(page, "unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [] })).toMatchObject({ ok: false, error: "browser_blocked" });
  await expect(vaultFrame(page).locator("#status")).toContainText("Safari");
});

test("sejf otwarty jako strona najwyższego poziomu odmawia pracy (rozstrzygnięcie 9)", async ({ page }) => {
  await page.goto(`${VAULT}${VAULT_PATH}`);
  await expect(page.locator("#status")).toHaveText("Sejf działa wyłącznie osadzony w panelu bobik-2.");
});

test("Chromium: ancestorOrigins w iframe z referrerpolicy=no-referrer nie blokuje rodzica (P6)", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "location.ancestorOrigins istnieje tylko w Chromium");
  await openPanel(page);
  const ancestors = await vaultFrameHandle(page).evaluate(() => Array.from(location.ancestorOrigins));
  console.log(`ancestorOrigins w ramce sejfu: ${JSON.stringify(ancestors)}`);
  expect([["http://127.0.0.1:8000"], ["null"]]).toContainEqual(ancestors);
  expect(await call(page, "hello")).toMatchObject({ ok: true });
});
