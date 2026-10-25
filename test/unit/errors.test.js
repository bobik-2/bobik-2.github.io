import { expect, it, vi } from "vitest";
import { codeOf, VaultError } from "../../src/errors.js";
import { ProtocolError } from "../../src/protocol.js";
import { WebAuthnError } from "../../src/webauthn.js";

it("kody z błędów sejfu, protokołu i WebAuthn", () => {
  expect(codeOf(new VaultError("bad_args"))).toBe("bad_args");
  expect(codeOf(new ProtocolError("bad_id"))).toBe("bad_id");
  expect(codeOf(new WebAuthnError("no_prf"))).toBe("no_prf");
});

it("nieprzewidziany wyjątek -> internal, w logu wyłącznie typ, bez treści", () => {
  const log = { error: vi.fn() };
  expect(codeOf(new TypeError("Grażyna Kowalska"), log)).toBe("internal");
  expect(log.error).toHaveBeenCalledWith("sejf: nieprzewidziany błąd", "TypeError");
  expect(JSON.stringify(log.error.mock.calls)).not.toContain("Grażyna");
});

it("obiekt z polem code, który nie jest błędem sejfu -> internal", () => {
  const log = { error: vi.fn() };
  expect(codeOf({ code: "bad_args" }, log)).toBe("internal");
});
