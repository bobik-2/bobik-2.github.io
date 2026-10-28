import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { ALLOWED_PARENT_ORIGINS, VERSION } from "../../src/config.js";

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

// Końcowy przegląd, I-3: v0.2.0 ufa atrapie panelu http://127.0.0.1:8000. Wydana wersja żyje dalej, więc
// wydanie z hostami produkcyjnymi musi unieważnić każdą wcześniejszą wersję z loopbackiem — inaczej
// dowolny proces na 127.0.0.1:8000 u lekarza dalej rozmawia z sejfem pod produkcyjnym RP ID.
const LOOPBACK = /^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?$/;
const LOOPBACK_RELEASES = ["0.1.0", "0.2.0"];

function productionViolations(origins, revoked) {
  if (origins.every((o) => LOOPBACK.test(o))) return []; // wersja nie do użytku klinicznego (P12)
  return [
    ...origins.filter((o) => !o.startsWith("https://")).map((o) => `origin ${o} w wersji z hostem produkcyjnym`),
    ...LOOPBACK_RELEASES.filter((v) => !revoked.includes(v)).map((v) => `${v} (loopback) nie jest unieważniona`),
  ];
}

it("I-3: reguła — wersja z hostem produkcyjnym tylko z https:// i z unieważnionymi 0.1.0, 0.2.0", () => {
  expect(productionViolations(["http://127.0.0.1:8000"], ["0.1.0"])).toEqual([]);
  expect(productionViolations(["https://panel.example"], ["0.1.0"])).toEqual(["0.2.0 (loopback) nie jest unieważniona"]);
  expect(productionViolations(["https://panel.example", "http://127.0.0.1:8000"], ["0.1.0", "0.2.0"])).toEqual([
    "origin http://127.0.0.1:8000 w wersji z hostem produkcyjnym",
  ]);
  expect(productionViolations(["https://panel.example"], ["0.1.0", "0.2.0"])).toEqual([]);
});

it("I-3: bieżąca konfiguracja spełnia regułę", () => {
  const { revoked } = JSON.parse(read("public/revoked.json"));
  expect(productionViolations(ALLOWED_PARENT_ORIGINS, revoked)).toEqual([]);
});
