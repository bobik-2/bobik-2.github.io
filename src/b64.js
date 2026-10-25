// base64url bez paddingu (RFC 4648 §5) — format bajtów w protokole (F8).

export class B64Error extends Error {
  constructor() {
    super("bad_base64url");
    this.name = "B64Error";
  }
}

export function toB64url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

// Ściśle jak bobik2.crypto.b64url: alfabet [A-Za-z0-9_-], bez "=", długość ≠ 4k+1.
export function fromB64url(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) throw new B64Error();
  const s = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  return Uint8Array.from(s, (c) => c.charCodeAt(0));
}
