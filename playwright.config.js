import { defineConfig, devices } from "@playwright/test";
import { VERSION } from "./src/config.js";

// Sejf na localhost (poprawny RP ID), panel na 127.0.0.1 — inne originy i inne site'y, jak w
// produkcji. Drugi panel (8002) jest spoza ALLOWED_PARENT_ORIGINS (test „obcy origin").
export const PANEL = "http://127.0.0.1:8000";
export const FOREIGN_PANEL = "http://127.0.0.1:8002";
export const VAULT = "http://localhost:8001";
export const VAULT_PATH = `/v${VERSION}/`;

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
      command: "node scripts/serve.mjs 8002 127.0.0.1 /=test/e2e/panel",
      url: `${FOREIGN_PANEL}/`,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: `node scripts/serve.mjs 8001 localhost /=public /v${VERSION}=src --dev-config`,
      url: `${VAULT}/revoked.json`,
      reuseExistingServer: !process.env.CI,
    },
  ],
});
