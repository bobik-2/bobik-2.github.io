import { expect, test } from "@playwright/test";
import { FOREIGN_PANEL, PANEL, VAULT, VAULT_PATH } from "../../playwright.config.js";
import { VERSION } from "../../src/config.js";
import { call, openPanel, vaultFrame, vaultFrameHandle } from "./helpers.js";

test("hello: wersja, stan, przeglądarka (moduły i wendorowane HPKE ładują się pod CSP)", async ({ page, browserName }) => {
  await openPanel(page);
  const res = await call(page, "hello");
  const blocked = browserName === "webkit";
  expect(res).toMatchObject({ v: 1, ok: true, result: { version: VERSION, revoked: false, browser_ok: !blocked, state: blocked ? "refusing" : "locked" } });
  expect([true, false, null]).toContain(res.result.prf);
});

test("P-4 / P-3: panel spoza listy originów nie dostaje żadnej odpowiedzi", async ({ page, browserName }) => {
  await openPanel(page, { base: FOREIGN_PANEL });
  // Kontrola pozytywna (przegląd 9–10, L-2): sejf w ramce działa — data-state ustawia dopiero render()
  // z vault.js (statyczny #status z index.html tego nie dowodzi) — a mimo to milczy.
  await expect(vaultFrame(page).locator("body")).toHaveAttribute("data-state", browserName === "webkit" ? "refusing" : "locked");
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

// Wartości zmierzone w Playwright 1.64.1 dla iframe'a z referrerpolicy="no-referrer" (jak w B2):
// Chromium i WebKit nie maskują, Firefox maskuje do "null".
const B2_ANCESTORS = { chromium: ["http://127.0.0.1:8000"], webkit: ["http://127.0.0.1:8000"], firefox: ["null"] };

test("ancestorOrigins w iframe z referrerpolicy=no-referrer: zmierzona wartość, rodzic przyjęty (P6)", async ({ page, browserName }) => {
  await openPanel(page);
  const ancestors = await vaultFrameHandle(page).evaluate(() => Array.from(location.ancestorOrigins ?? []));
  console.log(`ancestorOrigins w ramce sejfu (${browserName}): ${JSON.stringify(ancestors)}`);
  expect(ancestors).toEqual(B2_ANCESTORS[browserName]);
  expect(await call(page, "hello")).toMatchObject({ ok: true });
});

// Automatyczny przegląd bezpieczeństwa: dozwolony panel osadzony w obcej stronie (z no-referrer i bez)
// nie dostaje odpowiedzi — w Firefoksie także wtedy, gdy przodkowie są zamaskowani do "null".
for (const policy of ["no-referrer", ""]) {
  test(`dozwolony panel w ramce obcej strony (referrerpolicy=${policy || "domyślna"}) -> brak odpowiedzi`, async ({ page, browserName }) => {
    await page.goto(`${FOREIGN_PANEL}/?${new URLSearchParams({ vault_path: VAULT_PATH })}`);
    await page.evaluate(
      ([url, rp]) =>
        new Promise((resolve) => {
          const f = document.createElement("iframe");
          f.id = "wrapped-panel";
          if (rp) f.referrerPolicy = rp;
          f.width = 800;
          f.height = 600;
          f.addEventListener("load", resolve, { once: true });
          f.src = url;
          document.body.append(f);
        }),
      [`${PANEL}/?${new URLSearchParams({ vault_path: VAULT_PATH })}`, policy],
    );
    const panel = page.frames().find((f) => f.url().startsWith(PANEL));
    await panel.evaluate(() => window.vaultReady);
    // Kontrola pozytywna: sejf w zagnieżdżonej ramce działa (render() ustawił data-state).
    await expect(page.frameLocator("#wrapped-panel").frameLocator("#vault").locator("body")).toHaveAttribute(
      "data-state",
      browserName === "webkit" ? "refusing" : "locked",
    );
    expect(await panel.evaluate(() => window.vaultCall("hello", {}, 2_000))).toEqual({ timeout: true });
  });
}
