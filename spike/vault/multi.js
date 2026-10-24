// SPIKE (throwaway): jeden get() dla dwóch kluczy z różnymi solami (evalByCredential).
const out = document.getElementById("out");
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const creds = []; // {id, salt}
const log = [];
const report = (e) => { log.push(e); out.textContent = JSON.stringify(log, null, 1); };

document.getElementById("create").onclick = async () => {
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: location.hostname, name: "spike" },
      user: { id: new Uint8Array(16), name: "lekarz", displayName: "Lekarz" },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: creds.map((c) => ({ type: "public-key", id: c.id })),
      authenticatorSelection: { residentKey: "discouraged", userVerification: "discouraged" },
      extensions: { prf: {} },
    } });
    creds.push({ id: cred.rawId, salt: crypto.getRandomValues(new Uint8Array(32)) });
    report({ op: "create", ok: true, id: b64url(cred.rawId) });
  } catch (e) { report({ op: "create", ok: false, error: `${e.name}: ${e.message}` }); }
};

async function get(op, publicKeyExtra, allow) {
  try {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)), rpId: location.hostname,
      allowCredentials: allow.map((c) => ({ type: "public-key", id: c.id })),
      userVerification: "discouraged", ...publicKeyExtra,
    } });
    report({ op, ok: true, id: b64url(a.rawId), prf_first: a.getClientExtensionResults().prf?.results?.first ? b64(a.getClientExtensionResults().prf.results.first) : null });
  } catch (e) { report({ op, ok: false, error: `${e.name}: ${e.message}` }); }
}
window.spikeSingle = (i) => get(`single${i}`, { extensions: { prf: { eval: { first: creds[i].salt } } } }, [creds[i]]);
document.getElementById("multi").onclick = () => get("multi", {
  extensions: { prf: { evalByCredential: Object.fromEntries(creds.map((c) => [b64url(c.id), { first: c.salt }])) } },
}, creds);
document.getElementById("single").onclick = () => window.spikeSingle(Number(document.body.dataset.i ?? 0));
