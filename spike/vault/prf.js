// SPIKE (throwaway): WebAuthn create()/get() z PRF w iframe'ie.
const out = document.getElementById("out");
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const salt1 = new TextEncoder().encode("bobik-spike-salt-1".padEnd(32, "."));
const salt2 = new TextEncoder().encode("bobik-spike-salt-2".padEnd(32, "."));
window.spike = { log: [] };
let credId = null;

function report(entry) {
  window.spike.log.push(entry);
  out.textContent = JSON.stringify(window.spike.log, null, 1);
}

document.getElementById("create").onclick = async () => {
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { id: location.hostname, name: "bobik-sejf spike" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "lekarz", displayName: "Lekarz" },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "discouraged", userVerification: "discouraged" },
      extensions: { prf: { eval: { first: salt1 } } },
    } });
    credId = cred.rawId;
    const prf = cred.getClientExtensionResults().prf ?? null;
    report({ op: "create", ok: true, prf_enabled: prf?.enabled ?? null, prf_first: prf?.results?.first ? b64(prf.results.first) : null });
  } catch (e) {
    report({ op: "create", ok: false, error: `${e.name}: ${e.message}` });
  }
};

async function get(op, salt) {
  try {
    const a = await navigator.credentials.get({ publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId: location.hostname,
      allowCredentials: credId ? [{ type: "public-key", id: credId }] : [],
      userVerification: "discouraged",
      extensions: { prf: { eval: { first: salt } } },
    } });
    const prf = a.getClientExtensionResults().prf ?? null;
    report({ op, ok: true, prf_first: prf?.results?.first ? b64(prf.results.first) : null });
  } catch (e) {
    report({ op, ok: false, error: `${e.name}: ${e.message}` });
  }
}
document.getElementById("get").onclick = () => get("get", salt1);
document.getElementById("get2").onclick = () => get("get2", salt2);
