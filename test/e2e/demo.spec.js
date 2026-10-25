import { expect, test } from "@playwright/test";
import { VAULT, VAULT_PATH } from "../../playwright.config.js";

const OPTS = { protocol: "ctap2", ctap2Version: "ctap2_1", transport: "usb", hasResidentKey: true,
  hasUserVerification: true, isUserVerified: true, hasPrf: true, automaticPresenceSimulation: true };

const DEMO = `${VAULT}${VAULT_PATH}demo.html`;

test.describe("demo — WebAuthn (wirtualny authenticator)", () => {
  test.skip(({ browserName }) => browserName !== "chromium", "wirtualny authenticator tylko przez CDP (Chromium)");

  test("dodaj dwa klucze, sprawdź włożony, zapomnij", async ({ page, context }) => {
    const cdp = await context.newCDPSession(page);
    await cdp.send("WebAuthn.enable", { enableUI: false });
    const a1 = (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: OPTS })).authenticatorId;
    await page.goto(DEMO);
    await expect(page.locator("#browser")).toContainText("Dopuszczona przez sejf");

    await page.fill("#key-name", "niebieski");
    await page.click("#add");
    await expect(page.locator("#keys tbody tr")).toHaveCount(1);

    // ten sam YubiKey drugi raz -> odmowa
    await page.fill("#key-name", "duplikat");
    await page.click("#add");
    await expect(page.locator("#log")).toContainText("już zarejestrowany");
    await expect(page.locator("#keys tbody tr")).toHaveCount(1);

    await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: a1 });
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: OPTS });
    await page.fill("#key-name", "czerwony");
    await page.click("#add");
    await expect(page.locator("#keys tbody tr")).toHaveCount(2);

    const rows = page.locator("#keys tbody tr");
    await expect(rows.nth(0)).toContainText("localhost");
    await expect(rows.nth(1).locator("td").nth(6)).toHaveText(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);

    // włożony jest tylko „czerwony"
    await page.click("#check-all");
    await expect(rows.nth(1)).toContainText("sekret zgodny");
    await expect(rows.nth(1)).toHaveClass("hit");
    await expect(rows.nth(0)).not.toHaveClass("hit");

    // po odświeżeniu lista zostaje (localStorage)
    await page.reload();
    await expect(page.locator("#keys tbody tr")).toHaveCount(2);

    page.once("dialog", (d) => d.accept());
    await page.locator("#keys tbody tr", { hasText: "niebieski" }).getByRole("button", { name: "Zapomnij" }).click();
    await expect(page.locator("#keys tbody tr")).toHaveCount(1);
    await expect(page.locator("#keys tbody tr")).toContainText("czerwony");
  });
});

test("demo nie proponuje authenticatora platformowego (Touch ID / Windows Hello)", async ({ page, context, browserName }) => {
  test.skip(browserName !== "chromium", "wirtualny authenticator tylko przez CDP (Chromium)");
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { ...OPTS, transport: "internal" } });
  await page.goto(DEMO);
  await page.fill("#key-name", "touch id");
  await page.click("#add");
  // authenticatorAttachment: "cross-platform" -> przeglądarka pomija wbudowany
  // authenticator i czeka na klucz sprzętowy; nic nie zostaje zarejestrowane.
  // (Odrzucenie po stronie JS, gdyby przeglądarka go jednak użyła — testy jednostkowe.)
  await page.waitForTimeout(3000);
  await expect(page.locator("#keys tbody tr")).toHaveCount(0);
  await expect(page.locator("#log")).not.toContainText("dodano");
});

test("demo ładuje się i pokazuje stan przeglądarki", async ({ page, browserName }) => {
  await page.goto(DEMO);
  await expect(page.locator("#rp-id")).toHaveText("localhost");
  const allowed = page.locator("#browser dt", { hasText: "Dopuszczona przez sejf" }).locator("+ dd");
  if (browserName === "webkit") {
    await expect(allowed).toContainText("Safari/WebKit zablokowany");
    await expect(page.locator("#add")).toBeDisabled();
  } else {
    await expect(allowed).toHaveText("tak");
    await expect(page.locator("#add")).toBeEnabled();
  }
  await expect(page.locator("#browser")).toContainText("Unieważniona");
});
