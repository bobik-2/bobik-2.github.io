// Skrypty testowe dla context.addInitScript. Playwright wstrzykuje je do każdej ramki kontekstu,
// także do ramki sejfu na innym originie. Kodu sejfu nie podmieniają (decyzja planu P13).

// P-2: wirtualny authenticator CDP zawsze zwraca PRF przy create(), a YubiKey z firmware < 5.8 nie
// (brak hmac-secret-mc) — zdejmujemy prf.results z wyniku rejestracji, `enabled` zostaje.
export function stripPrfAtCreate() {
  if (typeof PublicKeyCredential === "undefined") return;
  const original = PublicKeyCredential.prototype.getClientExtensionResults;
  PublicKeyCredential.prototype.getClientExtensionResults = function () {
    const results = original.call(this);
    if (this.response instanceof AuthenticatorAttestationResponse && results.prf) {
      return { ...results, prf: { enabled: results.prf.enabled } };
    }
    return results;
  };
}

// P-3: przesuwalny Date.now() — okno limitu (5 min) bez czekania.
export function shiftableClock() {
  const realNow = Date.now.bind(Date);
  let offset = 0;
  Object.defineProperty(window, "__bobikShiftClock", {
    value: (ms) => {
      offset += ms;
    },
  });
  Date.now = () => realNow() + offset;
}
