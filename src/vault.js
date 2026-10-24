import { ALLOWED_PARENT_ORIGINS, VERSION } from "./config.js";
import { errorResponse, okResponse, parseRequest, ProtocolError } from "./protocol.js";
import { fetchRevoked, isRevoked } from "./revocation.js";
import { browserOk } from "./browser.js";

const revokedPromise = fetchRevoked(fetch, new URL("../revoked.json", import.meta.url));

const handlers = {
  async hello() {
    const doc = await revokedPromise;
    return { version: VERSION, revoked: isRevoked(VERSION, doc), browser_ok: browserOk(window) };
  },
};

window.addEventListener("message", async (event) => {
  if (event.source !== window.parent) return;
  if (!ALLOWED_PARENT_ORIGINS.includes(event.origin)) return;
  let id = null;
  try {
    const req = parseRequest(event.data);
    id = req.id;
    const handler = Object.hasOwn(handlers, req.op) ? handlers[req.op] : null;
    if (!handler) throw new ProtocolError("unknown_op");
    const result = await handler(req);
    event.source.postMessage(okResponse(id, result), event.origin);
  } catch (e) {
    const code = e instanceof ProtocolError ? e.code : "internal";
    event.source.postMessage(errorResponse(id, code), event.origin);
  }
});
