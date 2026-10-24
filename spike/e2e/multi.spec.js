// SPIKE (throwaway): unlock z dwoma YubiKeyami w jednym get().
import { expect, test } from "@playwright/test";

const OPTS = { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb", hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true };

test("evalByCredential: odpowiada klucz, którego sól pasuje; rawId wskazuje który", async ({ page, context }) => {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  const a1 = (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: OPTS })).authenticatorId;
  await page.goto("/multi.html");
  const fl = page.frameLocator("#vault");
  const out = fl.locator("#out");
  const logOf = async () => JSON.parse(await out.textContent());
  const click = async (sel, n) => { await fl.locator(sel).click(); await expect.poll(async () => (await logOf()).length).toBe(n); };

  await click("#create", 1);                                           // YubiKey 1
  await cdp.send("WebAuthn.setUserVerified", { authenticatorId: a1, isUserVerified: true });
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: a1 }); // wyjmij YubiKey 1
  const a2 = (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: OPTS })).authenticatorId;
  await click("#create", 2);                                           // YubiKey 2
  await click("#single", 3);                                           // eval tylko dla wyjętego YubiKeya 1 -> NotAllowedError
  await click("#multi", 4);
  const log = await logOf();
  console.log(JSON.stringify(log, null, 1));
  const [c1, c2, , multi] = log;
  expect(c1.ok && c2.ok).toBe(true);
  expect(multi.ok).toBe(true);
  expect(multi.id).toBe(c2.id); // włożony jest tylko YubiKey 2
  // wynik multi = wynik pojedynczego eval z solą klucza 2
  await fl.locator("body").evaluate((b) => { b.dataset.i = "1"; });
  await click("#single", 5);
  expect((await logOf())[4].prf_first).toBe(multi.prf_first);
  expect(multi.prf_first).toBeTruthy();
  void a2;
});
