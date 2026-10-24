import { defineConfig, devices } from "@playwright/test";

// Sejf na localhost (poprawny RP ID), panel na 127.0.0.1 — inne originy
// i inne site'y, jak w produkcji.
export const PANEL = "http://127.0.0.1:8000";
export const VAULT = "http://localhost:8001";

export default defineConfig({
  testDir: "test/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: PANEL },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    // WebKit tylko do sprawdzenia blokady Safari (D13).
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: [
    {
      command: "node scripts/serve.mjs 8000 127.0.0.1 /=test/e2e/panel",
      url: `${PANEL}/`,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: "node scripts/serve.mjs 8001 localhost /=public /v0.1.0=src",
      url: `${VAULT}/revoked.json`,
      reuseExistingServer: !process.env.CI,
    },
  ],
});
