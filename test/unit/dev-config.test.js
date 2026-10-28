import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { DEV_PARENT_ORIGINS, rewriteParentOrigins } from "../../scripts/dev-config.mjs";
import { ALLOWED_PARENT_ORIGINS, VERSION } from "../../src/config.js";

const SRC = readFileSync(new URL("../../src/config.js", import.meta.url), "utf8");

// Podmieniony config jako prawdziwy moduł ES (plik tymczasowy — bez zależności od obsługi data: URL).
function load(text) {
  const file = join(mkdtempSync(join(tmpdir(), "sejf-config-")), "config.mjs");
  writeFileSync(file, text);
  return import(pathToFileURL(file).href);
}

describe("originy panelu: produkcja i podmiana dev/E2E (rozstrzygnięcie 11, P9, P12)", () => {
  it("VERSION 0.3.0; lista produkcyjna = panel bobik-2 pod https://bobik.iplweb.pl", () => {
    expect(VERSION).toBe("0.3.0");
    expect(ALLOWED_PARENT_ORIGINS).toEqual(["https://bobik.iplweb.pl"]);
    expect(Object.isFrozen(ALLOWED_PARENT_ORIGINS)).toBe(true);
  });

  it("--dev-config: atrapa panelu i dev bobik-2; VERSION bez zmian", async () => {
    const mod = await load(rewriteParentOrigins(SRC, DEV_PARENT_ORIGINS));
    expect(mod.ALLOWED_PARENT_ORIGINS).toEqual(["http://127.0.0.1:8000", "http://localhost:8000"]);
    expect(mod.VERSION).toBe(VERSION);
  });

  it("--parent-origins: dowolna lista (np. live_server B3)", async () => {
    const mod = await load(rewriteParentOrigins(SRC, ["http://localhost:8123"]));
    expect(mod.ALLOWED_PARENT_ORIGINS).toEqual(["http://localhost:8123"]);
  });

  it("brak znaczników albo dwa bloki -> błąd", () => {
    expect(() => rewriteParentOrigins("export const X = 1;\n", DEV_PARENT_ORIGINS)).toThrow(/parent-origins/);
    expect(() => rewriteParentOrigins(SRC + SRC, DEV_PARENT_ORIGINS)).toThrow(/parent-origins/);
  });

  it("niepoprawny origin -> błąd", () => {
    for (const bad of ["javascript:alert(1)", "http://localhost:8000/", "https://a.example/x", '"),alert(1),("']) {
      expect(() => rewriteParentOrigins(SRC, [bad])).toThrow(/origin/);
    }
  });
});
