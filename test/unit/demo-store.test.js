import { expect, it } from "vitest";
import { createStore } from "../../src/demo-store.js";

function memStorage() {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
}

const entry = (id) => ({ credentialId: id, name: `klucz ${id}`, rpId: "bobik-2.github.io", salt: "c2Fs", createdAt: "2026-10-24T12:00:00Z", prfAtCreate: false, secretFingerprint: "AAAA" });

it("dodaje, listuje i zapomina klucze", () => {
  const s = createStore(memStorage());
  expect(s.list()).toEqual([]);
  s.add(entry("a"));
  s.add(entry("b"));
  expect(s.list().map((e) => e.credentialId)).toEqual(["a", "b"]);
  s.remove("a");
  expect(s.list().map((e) => e.credentialId)).toEqual(["b"]);
});

it("przeżywa nowy obiekt store na tym samym storage", () => {
  const st = memStorage();
  createStore(st).add(entry("a"));
  expect(createStore(st).list()).toHaveLength(1);
});

it("storage rzucający wyjątki (tryb prywatny) -> działa w pamięci", () => {
  const broken = { getItem() { throw new Error("x"); }, setItem() { throw new Error("x"); }, removeItem() { throw new Error("x"); } };
  const s = createStore(broken);
  s.add(entry("a"));
  expect(s.list()).toHaveLength(1);
  expect(s.persistent()).toBe(false);
});

it("uszkodzony JSON -> pusta lista", () => {
  const st = memStorage();
  st.setItem("bobik-sejf/demo/keys/v1", "{nie json");
  expect(createStore(st).list()).toEqual([]);
});
