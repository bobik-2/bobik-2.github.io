import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { fingerprint } from "../../src/fingerprint.js";
import { BOBIK2, b } from "../helpers/vectors.js";

const DIR = new URL("../vectors/", import.meta.url);
const sums = readFileSync(new URL("SHA256SUMS", DIR), "utf8").trim().split("\n").map((line) => line.split("  "));

it("SHA256SUMS: każdy wektor ma zapisaną sumę", () => {
  for (const [sum, name] of sums) {
    expect(createHash("sha256").update(readFileSync(new URL(name, DIR))).digest("hex"), name).toBe(sum);
  }
});

it("bobik2_v1.json to kopia 1:1 z bobik-2 (suma z SHA256SUMS bobik-2)", () => {
  expect(Object.fromEntries(sums.map(([s, n]) => [n, s]))["bobik2_v1.json"]).toBe(
    "f9ca1b3c31633e85c4648305e1cc0057927074cf2cbf6254d91ca5bd670ece50",
  );
});

// Kopia sejf_v1.json żyje w bobik-2 (test S-1). `npm run vectors` przepisuje i plik, i SHA256SUMS,
// więc bez literału przypadkowa regeneracja przeszłaby zielono, a kopie by się rozjechały.
it("sejf_v1.json nie został zregenerowany (suma przypięta literałem, jak kopia w bobik-2)", () => {
  expect(Object.fromEntries(sums.map(([s, n]) => [n, s]))["sejf_v1.json"]).toBe(
    "181268aa8304f8fe6d98078c82a1441f412455e86901d3368e33e0305a89b3a5",
  );
});

it("F7: odciski liczone w sejfie = odciski z bobik-2 (bobik2.crypto.fingerprint)", async () => {
  expect(await fingerprint(b(BOBIK2.clinic.public_key_spki_der))).toBe(BOBIK2.clinic.fingerprint);
  expect(await fingerprint(b(BOBIK2.rsa_lease_key.public_key_spki_der))).toBe(BOBIK2.rsa_lease_key.fingerprint);
});
