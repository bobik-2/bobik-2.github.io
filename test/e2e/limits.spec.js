import { expect, test } from "@playwright/test";
import { authenticators, call, clickInVault, fakeInterviews, grantBobik2Clinic, openPanel, register, shiftClock, unlock, vaultFrame } from "./helpers.js";
import { shiftableClock } from "./shims.js";

test.skip(({ browserName }) => browserName !== "chromium", "wirtualne authenticatory tylko przez CDP (Chromium) — B-R9");

const FIVE_MIN = 5 * 60_000;

test("P-3: rate_limited w oknie, a 51. wywiad w sesji blokuje sejf (locked/limit)", async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.addInitScript(shiftableClock);
  const auth = await authenticators(context, page);
  await openPanel(page);
  const reg = await register(page, auth, { doctorId: 17, displayName: "dr Anna Nowak" });
  await unlock(page, reg, 17);
  await grantBobik2Clinic(page, reg, 17);
  const interviews = await fakeInterviews(51);

  expect(await call(page, "open", { interviews: interviews.slice(0, 10), items: [] })).toMatchObject({ ok: true });
  expect(await call(page, "open", { interviews: [interviews[10]], items: [] })).toMatchObject({ ok: false, error: "rate_limited" });
  await expect(vaultFrame(page).locator("#counter")).toContainText("Wywiady: 10/50");
  for (let round = 1; round < 5; round++) {
    await shiftClock(page, FIVE_MIN);
    expect(await call(page, "open", { interviews: interviews.slice(round * 10, round * 10 + 10), items: [] })).toMatchObject({ ok: true });
  }
  expect(await page.evaluate(() => window.vaultEvents)).toEqual([]);
  await shiftClock(page, FIVE_MIN);
  expect(await call(page, "open", { interviews: [interviews[50]], items: [] })).toMatchObject({ ok: false, error: "limit_reached" });
  await expect.poll(() => page.evaluate(() => window.vaultEvents)).toEqual([{ v: 1, event: "locked", reason: "limit" }]);
  await expect(vaultFrame(page).locator("#status")).toHaveText("Sejf zablokowany");
  expect(await call(page, "open", { interviews: [], items: [] })).toMatchObject({ ok: false, error: "locked" });
});

test("P-3: iframe bez allow=publickey-credentials-* -> register kończy się not_allowed", async ({ page, context }) => {
  const auth = await authenticators(context, page);
  await auth.insert();
  await openPanel(page, { noAllow: true });
  const pending = call(page, "register", { doctor_id: 17, display_name: "dr Anna Nowak" });
  await clickInVault(page, "Zarejestruj klucz 1");
  expect(await pending).toMatchObject({ ok: false, error: "not_allowed" });
});
