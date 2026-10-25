import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { sumsOf, walk } from "../../scripts/sums.mjs";

const VENDOR = "src/vendor";

it("SHA256SUMS opisuje dokładnie pliki w src/vendor", async () => {
  expect(await sumsOf(VENDOR, { exclude: ["SHA256SUMS"] })).toBe(readFileSync(join(VENDOR, "SHA256SUMS"), "utf8"));
});

it("importy statyczne bez gołych specyfikatorów (CSP: bez import map)", async () => {
  const offenders = [];
  for (const file of (await walk(VENDOR)).filter((f) => f.endsWith(".js"))) {
    readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      if (/^\s*(\*|\/\/)/.test(line)) return; // przykłady w JSDoc
      if (/\bfrom\s+["'](?![./])/.test(line)) offenders.push(`${file}:${i + 1}`);
    });
  }
  expect(offenders).toEqual([]);
});

it("src/vendor = node_modules w przypiętych wersjach (regeneracja daje te same sumy)", () => {
  const tmp = mkdtempSync(join(tmpdir(), "sejf-vendor-"));
  execFileSync("node", ["scripts/vendor-hpke.mjs", tmp]);
  expect(readFileSync(join(tmp, "SHA256SUMS"), "utf8")).toBe(readFileSync(join(VENDOR, "SHA256SUMS"), "utf8"));
}, 30_000);

it("moduł ładuje się ścieżką względną", async () => {
  const mod = await import("../../src/vendor/hpke-core-1.9.0/mod.js");
  expect(typeof mod.CipherSuite).toBe("function");
});
