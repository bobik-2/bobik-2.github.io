// Atrapa panelu: osadza sejf i wystawia window.vaultCall(op, args) dla testów.
const params = new URLSearchParams(location.search);
const VAULT_ORIGIN = params.get("vault_origin") ?? "http://localhost:8001";
const VAULT_PATH = params.get("vault_path") ?? "/v0.1.0/";

const frame = document.getElementById("vault");
const pending = new Map();
let seq = 0;

window.addEventListener("message", (event) => {
  if (event.origin !== VAULT_ORIGIN || event.source !== frame.contentWindow) return;
  const msg = event.data;
  const p = pending.get(msg?.id);
  if (!p) return;
  pending.delete(msg.id);
  p(msg);
});

window.vaultReady = new Promise((resolve) => frame.addEventListener("load", resolve, { once: true }));
frame.src = VAULT_ORIGIN + VAULT_PATH;

window.vaultCall = async (op, args = {}) => {
  await window.vaultReady;
  const id = `m${++seq}`;
  return new Promise((resolve) => {
    pending.set(id, resolve);
    frame.contentWindow.postMessage({ v: 1, id, op, ...args }, VAULT_ORIGIN);
  });
};
