import { expect, test } from "@playwright/test";

test("panel dostaje odpowiedź na hello z sejfu w iframe'ie", async ({ page, browserName }) => {
  await page.goto("/");
  const res = await page.evaluate(() => window.vaultCall("hello"));
  expect(res).toEqual({
    v: 1,
    id: expect.any(String),
    ok: true,
    result: { version: "0.1.0", revoked: false, browser_ok: browserName !== "webkit" },
  });
});
