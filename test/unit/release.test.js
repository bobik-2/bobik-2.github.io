import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { VERSION } from "../../src/config.js";

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");

it("0.1.0 (demo, origin E2E w konfiguracji) jest unieważniona, bieżąca wersja nie", () => {
  const { revoked } = JSON.parse(read("public/revoked.json"));
  expect(revoked).toContain("0.1.0");
  expect(revoked).not.toContain(VERSION);
});

it("package.json i src/config.js mają tę samą wersję", () => {
  expect(JSON.parse(read("package.json")).version).toBe(VERSION);
  expect(JSON.parse(read("package-lock.json")).version).toBe(VERSION);
});

it("strona główna originu wskazuje bieżącą wersję demo", () => {
  expect(read("public/index.html")).toContain(`href="v${VERSION}/demo.html"`);
});

it("README: jedyne odłożenie — hosty produkcyjne panelu (P12)", () => {
  expect(read("README.md")).toContain("TODO przed użyciem produkcyjnym");
});
