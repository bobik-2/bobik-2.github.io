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
- `src/demo.html` — demo i diagnostyka kluczy sprzętowych
  (https://bobik-2.github.io/v0.1.0/demo.html): rejestracja, sprawdzanie,
  lista kluczy (tylko w tej przeglądarce). Działa na originie sejfu, więc
  jest częścią sejfu — przegląd kodu jak dla sejfu.
- Publikacja: job `deploy` w CI, tylko z `main`, po zielonym `test`.

## Testy

```bash
npm ci
npx vitest run
npx playwright test      # panel: 127.0.0.1:8000, sejf: localhost:8001
```

## Hosting

Organizacja GitHub **`bobik-2`** (osobna od `iplweb`), repo
`bobik-2.github.io` → origin sejfu `https://bobik-2.github.io`, RP ID
WebAuthn `bobik-2.github.io`. W tej organizacji **nie może** być żadnych
innych stron Pages — dzieliłyby origin z sejfem.

Przed włączeniem Pages / pierwszą rejestracją kluczy (RP ID jest na zawsze):

- wymuszone 2FA w organizacji (klucze sprzętowe), minimum właścicieli,
- chroniona gałąź `main` z wymaganym zielonym CI i podpisanymi commitami,
- Pages na planie Free wymaga repo publicznego.
