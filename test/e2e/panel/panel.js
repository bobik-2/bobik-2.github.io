// Atrapa panelu bobik-2: osadza sejf (?vault_path=/vX.Y.Z/, opcjonalnie ?no_allow=1) i wystawia
// testom window.vaultCall(op, args, timeoutMs) oraz window.vaultEvents (zdarzenia sejfu).
const params = new URLSearchParams(location.search);
const VAULT_ORIGIN = params.get("vault_origin") ?? "http://localhost:8001";
const VAULT_PATH = params.get("vault_path");
if (!VAULT_PATH) throw new Error("atrapa panelu: brak ?vault_path=/vX.Y.Z/");

const frame = document.getElementById("vault");
if (params.get("no_allow") === "1") frame.removeAttribute("allow");
const pending = new Map();
let seq = 0;
window.vaultEvents = [];

window.addEventListener("message", (event) => {
  if (event.origin !== VAULT_ORIGIN || event.source !== frame.contentWindow) return;
  const msg = event.data;
  if (msg && typeof msg.event === "string") {
    window.vaultEvents.push(msg);
    return;
  }
  const resolve = pending.get(msg?.id);
  if (!resolve) return;
  pending.delete(msg.id);
  resolve(msg);
});

window.vaultReady = new Promise((resolve) => frame.addEventListener("load", resolve, { once: true }));
frame.src = VAULT_ORIGIN + VAULT_PATH;

window.vaultCall = async (op, args = {}, timeoutMs = 120_000) => {
  await window.vaultReady;
  const id = `m${++seq}`;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ timeout: true });
    }, timeoutMs);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    frame.contentWindow.postMessage({ v: 1, id, op, ...args }, VAULT_ORIGIN);
  });
};
