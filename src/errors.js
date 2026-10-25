// Błędy sejfu: zawsze kod z listy specu (sekcja „Kody błędów"), nigdy opis.
import { ProtocolError } from "./protocol.js";
import { WebAuthnError } from "./webauthn.js";

export class VaultError extends Error {
  constructor(code) {
    super(code);
    this.name = "VaultError";
    this.code = code;
  }
}

// Kod dla panelu. Nieprzewidziany wyjątek = `internal`, a w konsoli wyłącznie jego typ:
// treść mogłaby nieść dane (spec B, tabela kodów, wiersz `internal`).
export function codeOf(e, log = console) {
  if (e instanceof VaultError || e instanceof ProtocolError || e instanceof WebAuthnError) return e.code;
  log.error("sejf: nieprzewidziany błąd", e?.name ?? typeof e);
  return "internal";
}
