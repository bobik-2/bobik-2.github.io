// Koperta protokołu panel <-> sejf (postMessage).
// Żądanie: {v: 1, id, op, ...}; odpowiedź: {v: 1, id, ok, result | error}.

export const PROTOCOL_VERSION = 1;

export class ProtocolError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

export function parseRequest(data) {
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new ProtocolError("bad_message");
  }
  if (data.v !== PROTOCOL_VERSION) throw new ProtocolError("bad_version");
  if (typeof data.id !== "string" || data.id.length === 0 || data.id.length > 64) {
    throw new ProtocolError("bad_id");
  }
  if (typeof data.op !== "string") throw new ProtocolError("bad_op");
  return data;
}

export function okResponse(id, result) {
  return { v: PROTOCOL_VERSION, id, ok: true, result };
}

export function errorResponse(id, code) {
  return { v: PROTOCOL_VERSION, id, ok: false, error: code };
}
