// SPIKE (throwaway): PRF w cross-origin iframe + wirtualny authenticator CDP.
import { expect, test } from "@playwright/test";

async function addAuthenticator(cdp) {
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb", hasResidentKey: true,
      hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true },
  });
  return authenticatorId;
}

async function run(page, iframeId) {
  const fl = page.frameLocator(`#${iframeId}`);
  for (const btn of ["create", "get", "get2", "get"]) {
    await fl.locator(`#${btn}`).click();
    await expect(fl.locator("#out")).toContainText(`"op": "${btn}"`);
  }
  return fl.locator("#out").textContent().then(JSON.parse);
}

test("PRF: create + get w iframe'ie z allow (authenticator na stronie)", async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await addAuthenticator(cdp);
  await page.goto("/");
  const log = await run(page, "with-allow");
  console.log(JSON.stringify(log, null, 1));
  const [c, g1, g2, g1b] = log;
  expect(c.ok).toBe(true);
  expect(g1.ok && g2.ok && g1b.ok).toBe(true);
  expect(g1.prf_first).toBeTruthy();
  expect(g1b.prf_first).toBe(g1.prf_first);        // ta sama sól -> ten sam sekret
  expect(g2.prf_first).not.toBe(g1.prf_first);     // inna sól -> inny sekret
});

test("bez atrybutu allow create() w iframe'ie jest blokowane", async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await addAuthenticator(cdp);
  await page.goto("/");
  const fl = page.frameLocator("#no-allow");
  await fl.locator("#create").click();
  await expect(fl.locator("#out")).toContainText('"op": "create"');
  const log = JSON.parse(await fl.locator("#out").textContent());
  console.log(JSON.stringify(log));
  expect(log[0].ok).toBe(false);
});
