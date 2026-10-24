# Spike sejfu (handoff B, sekcja 10) — wyniki

Data: 2026-10-24 · Kod: `spike/` (throwaway, nie wchodzi do `src/`).

Uruchomienie:

```bash
npx vitest run --config spike/vitest.config.js          # HPKE vs bobik-2
(cd spike && npx playwright test)                        # PRF w iframe'ie (Chromium)
# wektory: (cd ../bobik-2 && uv run python ../bobik-sejf/spike/gen_vectors.py > ../bobik-sejf/spike/vectors.json)
```

## Sprawdzone automatycznie

### 3. `@hpke/core` 1.9.0 z nieeksportowalnym kluczem — ✅, z zastrzeżeniem

- Wektory wygenerowane **kodem bobik-2** (`crypto.hpke`, `crypto.envelope`):
  `clinic_wrap` → DEK → `Sealed` oraz `SealedToClinic` otwierają się w JS
  (Node WebCrypto) kluczem kliniki zaimportowanym z `extractable: false`.
  Pusty `aad`, kontekst w `info` — zgodne. Zły `info` → błąd.
- **Pułapka:** przekazanie do `createRecipientContext` samego prywatnego
  `CryptoKey` (bez pary) działa tylko dla ok. połowy kluczy. `@hpke/common`
  próbuje wyliczyć klucz publiczny eksportem JWK, a gdy klucz jest
  nieeksportowalny — z samej współrzędnej x, **zgadując znak y**
  (`_derivePublicKeyWithoutJwkExport`). Przy nieparzystym y powstaje zły
  `pkR` w `kem_context` → odszyfrowanie pada. Potwierdzone na 6 świeżych
  kluczach (3 parzyste — działa, 3 nieparzyste — błąd).
  **Wniosek do specu:** sejf zawsze przekazuje `CryptoKeyPair`
  `{privateKey (extractable:false), publicKey}`; publiczny trzyma obok
  prywatnego (z bazy albo z generowania).
- `@hpke/core` importuje `@hpke/common` gołym specyfikatorem — wendorowanie
  bez bundlera wymaga przepisania importów na ścieżki względne (import map
  inline blokuje `script-src 'self'`).

### 1. WebAuthn w cross-origin iframe — ✅ Chromium (wirtualny authenticator)

Panel `127.0.0.1:8010` (inny site), iframe sejfu `localhost:8011`:

- `create()` **i** `get()` z `prf` działają w iframe'ie z
  `allow="publickey-credentials-get; publickey-credentials-create"`
  (aktywacja = kliknięcie w iframe'ie).
- Bez `allow`: `NotAllowedError: The 'publickey-credentials-create' feature
  is not enabled in this document…` — test negatywny potwierdza, że iframe
  jest naprawdę cross-origin i polityka działa.

### 2. PRF przy `create()` — ✅ na wirtualnym, ❓ na YubiKeyu

- Wirtualny authenticator (ctap2_1, `hasPrf`) zwraca przy `create()`
  `prf.enabled = true` **i** `prf.results.first`, identyczne z późniejszym
  `get()` z tą samą solą. Inna sól → inny wynik.
- To **nie przesądza** o YubiKeyu: wynik PRF przy rejestracji wymaga
  `hmac-secret-mc` (CTAP 2.2); YubiKey 5 z firmware < 5.7 zwróci
  prawdopodobnie tylko `enabled: true`. Projekt rejestracji musi obsłużyć
  oba przypadki: brak `results` przy `create()` → od razu `get()` (drugie
  dotknięcie).

### 4. Wirtualny authenticator CDP z PRF — ✅

`WebAuthn.addVirtualAuthenticator` z `hasPrf: true` na sesji CDP **strony**
obsługuje też żądania z iframe'a innego originu. Nadaje się do E2E w
Chromium. Firefox i WebKit w Playwright nie mają wirtualnego
authenticatora → E2E WebAuthn tylko w Chromium; Firefox E2E = protokół
(`hello`, origin) bez WebAuthn.

## Ustalenie projektowe (z lektury API, nie z prototypu)

`wrapKey` wymaga klucza **eksportowalnego**. Klucz prywatny lekarza
odpakowany z `extractable: false` nie może być potem zapakowany dla
drugiego YubiKeya. Handoff („przy drugim pakuje ten sam prywatny, wymaga
odblokowania") trzeba doprecyzować: przy dodawaniu YubiKeya sejf ponownie
odpakowuje `wrapped_private` **jako eksportowalny, chwilowo**, pakuje dla
nowego klucza i porzuca tę kopię; albo oba YubiKeye rejestrowane w jednej
ceremonii zaraz po wygenerowaniu pary. Analogicznie `grant_clinic_access`:
sejf trzyma własny `ClinicKeyGrant.wrapped_private` i ponownie go otwiera
(HPKE → PKCS8 → HPKE do nowego lekarza), zamiast eksportować klucz kliniki.

## Do sprawdzenia ręcznie (sprzęt — po Twojej stronie)

- **5.** Firefox + YubiKey 5 + PRF na Windows (D13 zakłada ✅).
- **1.** to samo co wyżej na prawdziwym YubiKeyu w Chrome, Edge, Firefox
  (Windows), w cross-origin iframe'ie.
- **2.** czy YubiKey 5 (jaki firmware na komputerach szpitalnych?) zwraca
  PRF już przy `create()`.
- Blokada Safari (D13) — sejf ma ją w `browser_ok`, test w WebKit dopiero
  w B1.

Strona do ręcznego testu: `node scripts/serve.mjs 8010 127.0.0.1 /=spike/panel`
i `node scripts/serve.mjs 8011 localhost /=spike/vault`, potem
`http://127.0.0.1:8010/` → przyciski w górnym iframe'ie. Na Windows z
YubiKeyem panel i sejf muszą być dostępne z tej maszyny (np. oba serwery
uruchomione lokalnie na niej).
