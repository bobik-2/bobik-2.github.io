// Strona demo / diagnostyki sejfu: rejestracja i sprawdzanie YubiKeyów
// (WebAuthn PRF) na originie sejfu. Nic nie odszyfrowuje.

import { VERSION } from "./config.js";
import { fromB64url, toB64url } from "./b64.js";
import { browserOk, isWebKit } from "./browser.js";
import { createStore } from "./demo-store.js";
import { fingerprint } from "./fingerprint.js";
import { fetchRevoked, isRevoked } from "./revocation.js";
import { evaluatePrf, prfSupport, registerCredential } from "./webauthn.js";

const MESSAGES = {
  not_security_key: "to nie jest klucz sprzętowy (Touch ID / pęk kluczy iCloud / Windows Hello / telefon) — sejf przyjmuje tylko YubiKey",
  not_allowed: "anulowano albo minął czas (albo ten klucz nie jest zarejestrowany na tej domenie)",
  already_registered: "ten klucz jest już zarejestrowany na tej liście",
  no_prf: "klucz albo przeglądarka nie obsługuje PRF (hmac-secret)",
  no_keys: "lista kluczy jest pusta",
  unknown_credential: "odpowiedział klucz spoza listy",
  bad_rp_id: "przeglądarka odrzuciła domenę (RP ID)",
  webauthn_failed: "nieoczekiwany błąd WebAuthn",
};

const rpId = location.hostname;
const te = new TextEncoder();
const store = createStore(safeLocalStorage());
const status = new Map(); // credentialId -> {cls, text}
const $ = (sel) => document.querySelector(sel);

function safeLocalStorage() {
  try {
    return window.localStorage;
  } catch {
    return { getItem: () => null, setItem() { throw new Error("brak"); }, removeItem() {} };
  }
}

function log(text, cls) {
  const li = document.createElement("li");
  li.textContent = `${new Date().toLocaleTimeString("pl-PL")} — ${text}`;
  if (cls) li.className = cls;
  $("#log").prepend(li);
}

function errorText(e) {
  return MESSAGES[e?.code] ?? `${e?.name ?? "Error"}: ${e?.message ?? e}`;
}

// Odcisk sekretu PRF (separacja domeny), żeby pokazać, że sekret jest stały,
// nie pokazując samego sekretu.
const secretFingerprint = (prf) => fingerprint(new Uint8Array([...te.encode("bobik/demo-prf-fp|"), ...prf]));

function cell(text, cls) {
  const td = document.createElement("td");
  td.textContent = text;
  if (cls) td.className = cls;
  return td;
}

function renderKeys() {
  const tbody = $("#keys tbody");
  tbody.replaceChildren();
  const keys = store.list();
  $("#no-keys").hidden = keys.length > 0;
  $("#keys").hidden = keys.length === 0;
  $("#storage-warning").hidden = store.persistent();
  for (const k of keys) {
    const tr = document.createElement("tr");
    tr.dataset.credentialId = k.credentialId;
    const st = status.get(k.credentialId);
    if (st) tr.className = st.cls;
    const short = k.credentialId.length > 16 ? `${k.credentialId.slice(0, 8)}…${k.credentialId.slice(-6)}` : k.credentialId;
    const idCell = cell(short, "mono");
    idCell.title = k.credentialId;
    const actions = document.createElement("td");
    const check = document.createElement("button");
    check.textContent = "Sprawdź";
    check.dataset.action = "check";
    const forget = document.createElement("button");
    forget.textContent = "Zapomnij";
    forget.dataset.action = "forget";
    actions.append(check, " ", forget);
    tr.append(
      cell(k.name),
      cell(k.rpId, "mono"),
      idCell,
      cell(new Date(k.createdAt).toLocaleString("pl-PL")),
      cell(k.prfAtCreate ? "tak" : "nie (drugie dotknięcie)"),
      cell(`${(k.transports ?? []).join(", ") || "?"} / ${k.aaguid ?? "AAGUID ukryty"}`, "mono"),
      cell(k.secretFingerprint, "mono"),
      cell(st?.text ?? "—", st?.cls === "hit" ? "ok" : st?.cls === "bad" ? "bad-text" : undefined),
      actions,
    );
    tbody.append(tr);
  }
}

async function renderBrowser() {
  const prf = await prfSupport(window);
  const revokedDoc = await fetchRevoked(fetch, new URL("../revoked.json", import.meta.url));
  const rows = [
    ["Wersja sejfu", VERSION],
    ["Unieważniona", revokedDoc === null ? "nie udało się pobrać listy (sejf odmówi pracy)" : isRevoked(VERSION, revokedDoc) ? "TAK — sejf odmówi pracy" : "nie"],
    ["Domena (RP ID)", rpId],
    ["Przeglądarka", navigator.userAgent],
    ["WebAuthn", typeof window.PublicKeyCredential === "function" ? "jest" : "BRAK"],
    ["PRF (getClientCapabilities)", prf === null ? "przeglądarka nie podaje — sprawdzi to rejestracja" : prf ? "tak" : "NIE"],
    ["Dopuszczona przez sejf", browserOk(window) ? "tak" : isWebKit(navigator.userAgent) ? "NIE — Safari/WebKit zablokowany (D13)" : "NIE"],
  ];
  const dl = $("#browser");
  dl.replaceChildren();
  for (const [k, v] of rows) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v;
    dl.append(dt, dd);
  }
  if (!browserOk(window)) {
    for (const b of document.querySelectorAll("button, input")) b.disabled = true;
    log("ta przeglądarka nie jest dopuszczona przez sejf — przyciski wyłączone", "bad-text");
  }
}

const keyForEval = (k) => ({ credentialId: fromB64url(k.credentialId), salt: fromB64url(k.salt) });

async function addKey(name) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const existing = store.list();
  log(`rejestracja „${name}" — dotknij klucz`);
  const reg = await registerCredential(navigator.credentials, {
    rpId,
    rpName: "Sejf kluczy bobik (demo)",
    userId: crypto.getRandomValues(new Uint8Array(16)),
    userName: "demo",
    displayName: "Demo sejfu",
    salt,
    excludeIds: existing.map((k) => fromB64url(k.credentialId)),
  });
  let prf = reg.prfFirst;
  if (!prf) {
    log("klucz nie zwrócił sekretu przy rejestracji — dotknij go jeszcze raz");
    prf = (await evaluatePrf(navigator.credentials, { rpId, keys: [{ credentialId: reg.credentialId, salt }] })).prfFirst;
  }
  const entry = {
    credentialId: toB64url(reg.credentialId),
    name,
    rpId,
    salt: toB64url(salt),
    createdAt: new Date().toISOString(),
    prfAtCreate: reg.prfFirst !== null,
    secretFingerprint: await secretFingerprint(prf),
    aaguid: reg.aaguid,
    transports: reg.transports,
  };
  store.add(entry);
  status.set(entry.credentialId, { cls: "hit", text: "dodany" });
  log(`dodano „${name}", odcisk sekretu ${entry.secretFingerprint}`, "ok");
}

async function check(keys) {
  log(keys.length === 1 ? `sprawdzanie „${keys[0].name}" — dotknij klucz` : "sprawdzanie — dotknij dowolny klucz z listy");
  const res = await evaluatePrf(navigator.credentials, { rpId, keys: keys.map(keyForEval) });
  const k = keys[res.index];
  const fp = await secretFingerprint(res.prfFirst);
  status.clear();
  if (fp === k.secretFingerprint) {
    status.set(k.credentialId, { cls: "hit", text: "odpowiedział, sekret zgodny" });
    log(`odpowiedział „${k.name}", sekret zgodny`, "ok");
  } else {
    status.set(k.credentialId, { cls: "bad", text: "SEKRET NIEZGODNY" });
    log(`odpowiedział „${k.name}", ale sekret NIEZGODNY (${fp}) — ta przeglądarka zwraca niestabilny PRF (np. WebKit bug 311099); sejf nie będzie w niej działał`, "bad-text");
  }
}

async function guarded(fn) {
  const buttons = document.querySelectorAll("button");
  for (const b of buttons) b.disabled = true;
  try {
    await fn();
  } catch (e) {
    log(`błąd: ${errorText(e)}`, "bad-text");
  } finally {
    for (const b of buttons) b.disabled = false;
    renderKeys();
  }
}

$("#rp-id").textContent = rpId;
$("#add-form").addEventListener("submit", (ev) => {
  ev.preventDefault();
  const name = $("#key-name").value.trim();
  if (!name) return;
  guarded(async () => {
    await addKey(name);
    $("#key-name").value = "";
  });
});
$("#check-all").addEventListener("click", () => guarded(() => check(store.list())));
$("#keys tbody").addEventListener("click", (ev) => {
  const btn = ev.target.closest("button");
  if (!btn) return;
  const id = btn.closest("tr").dataset.credentialId;
  const k = store.list().find((e) => e.credentialId === id);
  if (btn.dataset.action === "check") guarded(() => check([k]));
  if (btn.dataset.action === "forget" && confirm(`Zapomnieć „${k.name}"? Klucz zostanie na YubiKeyu, zniknie tylko z tej listy.`)) {
    store.remove(id);
    status.delete(id);
    log(`zapomniano „${k.name}"`);
    renderKeys();
  }
});

renderKeys();
renderBrowser();
