// Pomocnicy E2E: atrapa panelu, wywołania sejfu, przyciski w ramce, wirtualne authenticatory CDP.
import { expect } from "@playwright/test";
import { PANEL, VAULT, VAULT_PATH } from "../../playwright.config.js";

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
