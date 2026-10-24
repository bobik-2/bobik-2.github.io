import { defineConfig, devices } from "@playwright/test";
export default defineConfig({
  testDir: "e2e",
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:8010" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    { command: "node scripts/serve.mjs 8010 127.0.0.1 /=spike/panel", url: "http://127.0.0.1:8010/", cwd: "..", reuseExistingServer: true },
    { command: "node scripts/serve.mjs 8011 localhost /=spike/vault", url: "http://localhost:8011/prf.html", cwd: "..", reuseExistingServer: true },
  ],
});
