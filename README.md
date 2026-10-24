# bobik-sejf

Sejf kluczy dla [bobik-2](https://github.com/iplweb/bobik-2): mała statyczna
strona osadzana w panelu lekarza jako iframe na **osobnym originie**.
Trzyma klucz prywatny lekarza i klucz prywatny kliniki wyłącznie jako
nieeksportowalne `CryptoKey` w pamięci; odblokowanie kluczem sprzętowym
(WebAuthn PRF). Z panelem rozmawia wyłącznie przez `postMessage`.

Kontekst i decyzje: spec A i handoff B w repo bobik-2
(`docs/superpowers/specs/2026-10-14-szyfrowanie-a-klucze-kms-dzierzawy-design.md`,
`docs/superpowers/specs/2026-10-24-sejf-b-handoff.md`).

## Układ

- `src/` — kod jednej wersji sejfu, publikowany pod `/v<VERSION>/`.
- `public/` — pliki w korzeniu originu (`revoked.json`).
- `scripts/build.mjs` — składa `dist/` + `SHA256SUMS` (bez bundlera).
- `test/unit/` — Vitest; `test/e2e/` — Playwright z atrapą panelu.

## Testy

```bash
npm ci
npx vitest run
npx playwright test      # panel: 127.0.0.1:8000, sejf: localhost:8001
```

## Hosting — uwaga

Sejf **nie może** być serwowany z `iplweb.github.io/…`: wszystkie strony
Pages organizacji dzielą jeden origin (i RP ID WebAuthn). Potrzebna własna
domena tego repo albo osobna organizacja do publikacji — przed pierwszą
rejestracją kluczy (RP ID jest na zawsze).
