# B1 — protokół i kryptografia sejfu kluczy (release v0.2.0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Sejf kluczy w wersji 0.2.0 z pełnym protokołem panel ↔ sejf (`hello`, `register`, `unlock`, `add_credential`, `load_clinic_key`, `create_clinic_key`, `grant_clinic_access`, `open`, `grant_lease`, `lock`), kryptografią F1–F7 zgodną z bobik-2, limitem odszyfrowań, polskim UI, buildem z podpisanych tagów i wektorami krzyżowymi `sejf_v1.json` dla B2.

**Architecture:** Statyczne moduły ES bez bundlera. Kryptografia w małych, czystych modułach `src/crypto/*.js` (WebCrypto + zwendorowane `@hpke/core`), rdzeń sejfu `src/core.js` (stany `refusing`/`locked`/`unlocked`, koperta, `busy`, limit, blokada) z operacjami w `src/ops/*.js`, a cała zależność od przeglądarki (DOM, `postMessage`, `navigator.credentials`) jest wstrzykiwana — dzięki temu Vitest testuje rdzeń w Node z atrapą authenticatora i atrapą UI. `src/vault.js` tylko spina rdzeń z oknem (filtr rodzica, UI, zegar). Build składa `dist/` wyłącznie z podpisanych tagów `v*`.

**Tech Stack:** WebCrypto (ECDH P-256, HKDF-SHA256, AES-256-GCM, RSA-OAEP-3072), WebAuthn PRF, `@hpke/core` 1.9.0 + `@hpke/common` 1.10.1 (wendorowane), Vitest 5.0.5 (Node ≥ 24), Playwright 1.64.1 (Chromium z wirtualnymi authenticatorami CDP, Firefox, WebKit), GitHub Actions + Pages, podpisy tagów SSH (`gpg.format=ssh`).

**Spec:** `/Volumes/SSD/Programowanie/bobik-2/docs/superpowers/specs/2026-10-24-szyfrowanie-b-sejf-design.md` (file:///Volumes/SSD/Programowanie/bobik-2/docs/superpowers/specs/2026-10-24-szyfrowanie-b-sejf-design.md) — wiążące: „Rozstrzygnięcia", „Formaty" F1–F8, „Protokół panel ↔ sejf", „Testy" (Wektory krzyżowe, V-1…V-8, P-1…P-5), wiersz B1 w „Podział na plany". Handoff: `/Volumes/SSD/Programowanie/bobik-2/docs/superpowers/specs/2026-10-24-sejf-b-handoff.md` (file:///Volumes/SSD/Programowanie/bobik-2/docs/superpowers/specs/2026-10-24-sejf-b-handoff.md), sekcje 3–4 wiążące, 7 (repo sejfu). Wyniki spike'a: `docs/2026-10-24-spike-wyniki.md` (file:///Volumes/SSD/Programowanie/bobik-sejf-feat-b1/docs/2026-10-24-spike-wyniki.md). Kontrakt `sejf_v1.json` dla B2: plan B2, zadanie 10 (`/Volumes/SSD/Programowanie/bobik-2/docs/superpowers/plans/2026-10-24-szyfrowanie-b2-serwer.md`, file:///Volumes/SSD/Programowanie/bobik-2/docs/superpowers/plans/2026-10-24-szyfrowanie-b2-serwer.md).

**Część serii:** A (bobik-2, gotowe) → B2 (bobik-2, scalone do `dev`: endpointy, `bobik2_v1.json`) ∥ **B1 (ten plan, repo sejfu)** → B3 (integracja panelu w bobik-2). B1 konsumuje `bobik2_v1.json` z B2 i oddaje `test/vectors/sejf_v1.json` do testu S-1 w B2 (zadanie 10 części B planu B2).

**Poza zakresem B1:** `vault_client.js` i strony panelu (B3), E2E przez bobik-2 (B3), hosty produkcyjne panelu w `ALLOWED_PARENT_ORIGINS` (patrz P12), rejestracja w oknie najwyższego poziomu (rozstrzygnięcie 15 — tylko jeśli test ręczny Firefoksa ją wymusi).

## Decyzje planu

| # | Decyzja | Dlaczego |
|---|---|---|
| P1 | `register` **nie** odblokowuje sejfu: para lekarza (z `extractable: true`) jest używana wyłącznie do dwóch `wrapKey` i porzucana. Przepływy 2–5 zaczynają od `unlock` | wynik `register` trzeba najpierw zapisać na serwerze (`POST doctor-key/`); klucz w pamięci bez zapisanego wrapu niczemu nie służy, a krótsze życie kopii eksportowalnej to mniejsze ryzyko (rozstrzygnięcie 14). Bufora PKCS8 nie ma — `wrapKey` nie wystawia go do JS |
| P2 | Kolumna „wymaga" w tabeli operacji to **stan minimalny**: `register`/`unlock`/`lock` działają w `locked` i `unlocked` (nie w `refusing`), reszta wymaga `unlocked` | zgodne z akapitem o stanach („`unlocked` przyjmuje wszystko"); `register` w stanie `unlocked` nie rusza bieżących kluczy |
| P3 | `busy` dotyczy operacji interaktywnych (`register`, `unlock`, `add_credential`, `create_clinic_key`, `grant_clinic_access`, `grant_lease`). Każda blokada (`lock`, przycisk „Zablokuj", bezczynność, wiek, limit) przerywa oczekujące potwierdzenie i podbija licznik epok: operacja, która zaczęła się przed blokadą, kończy się kodem `locked` i nie zapisuje kluczy | wynik policzony kluczami sprzed blokady nie może wrócić do panelu (Review Focus 1) |
| P4 | Potwierdzenie w UI sejfu wygasa po 120 s (`LIMITS.INTERACTION_TIMEOUT_MS`) → `user_rejected` | panel ma limit 120 s; bez limitu po stronie sejfu porzucona operacja trzymałaby `busy` na zawsze |
| P5 | `open`: element `sealed` **musi** mieć `interview_id`, a `blob` musi być tekstem base64url (`null` → `bad_args`); nadmiarowe klucze w obiektach są ignorowane; powtórzony `interview_id` w `interviews` → `bad_args`; `interviews` i `items` mogą być puste. `unlock` przyjmuje poświadczenia z `GET state/` wprost (nadmiarowe `id`, `label`, `created_at` są ignorowane) | B3 dokleja `interview_id` z `ciphertexts.interview` i pomija pola z `blob: null` (renderuje je jako puste). Notatka dla B3 w README |
| P6 | Filtr rodzica: `event.source === window.parent`, `event.origin ∈ ALLOWED_PARENT_ORIGINS`, a jeśli `location.ancestorOrigins` istnieje i `[0]` nie jest `"null"`, to `[0] === event.origin`. Wartość `"null"` (maskowanie przez `referrerpolicy="no-referrer"` iframe'a z B2) nie odrzuca — wtedy rozstrzyga `event.origin`, jak w Firefoksie | B2 osadza iframe z `referrerpolicy="no-referrer"`; Chromium może wtedy maskować `ancestorOrigins`. Zadanie 9 ma test, który zapisuje faktyczną wartość. **Zmienione po przeglądzie 9–10:** `ancestorOrigins` musi mieć **dokładnie jeden** wpis (sejf bezpośrednio w dokumencie panelu najwyższego poziomu), równy `event.origin` albo `"null"`. Zmierzone (Playwright 1.64.1, iframe z `no-referrer`): Chromium i WebKit `["http://127.0.0.1:8000"]`, Firefox `["null"]`; obca strona osadzająca panel daje zawsze 2 wpisy (Firefox: `["null","null"]` z `no-referrer`, `["null", obcy]` bez), więc odrzucenie po długości zamyka lukę także tam, gdzie wpisy są zamaskowane |
| P7 | Limit liczony pesymistycznie: każdy nowy `interview_id` z `interviews` liczy się przed odszyfrowaniem, także gdy jego `clinic_wrap` potem się nie otworzy; `grant_lease` liczy się dopiero po zatwierdzeniu przez lekarza (sprawdzany też przed pokazaniem pytania). Żądanie z > 10 nowymi wywiadami zawsze dostaje `rate_limited` — panel dzieli je na paczki ≤ 10 (notatka dla B3) | rozstrzygnięcie 1; brak „sondowania" bez kosztu |
| P8 | `@hpke/core` 1.9.0 i `@hpke/common` 1.10.1 wendorowane skryptem `scripts/vendor-hpke.mjs` z `node_modules` (wersje przypięte w `package.json`), z przepisaniem `from "@hpke/common"` na ścieżki względne i `src/vendor/SHA256SUMS`. Test regeneruje katalog i porównuje sumy | spec „Ochrona sejfu"; spike: import map inline łamie `script-src 'self'` |
| P9 | Konfiguracja dev/E2E: `scripts/serve.mjs --dev-config` (albo `--parent-origins=a,b`) podmienia przy serwowaniu blok między znacznikami `// <parent-origins>` … `// </parent-origins>` w `src/config.js`. Build nigdy jej nie widzi, bo składa `dist/` z `git archive` tagów | rozstrzygnięcie 11 |
| P10 | Build tylko z **podpisanych** tagów `vX.Y.Z` (SSH), weryfikowanych w CI przeciw `releases/allowed_signers` w repo; każdy tag ma `releases/<X.Y.Z>.sha256`; tag musi leżeć w historii `HEAD`; zmiana `src/` wydanej wersji bez podbicia `VERSION` łamie build. **Podpisywanie działa w tym środowisku** (sprawdzone 2026-10-25: `gpg.format=ssh`, `tag.gpgsign=true`, `ssh-keygen -Y sign/verify` OK), więc **nie ma odstępstwa** od rozstrzygnięcia 12 | rozstrzygnięcie 12 |
| P11 | Tag `v0.1.0` zakładany wstecznie na `f690d3a` (ostatni zielony deploy `main`), z porównaniem sum z opublikowanymi plikami `https://bobik-2.github.io/v0.1.0/…` przed zapisaniem `releases/0.1.0.sha256`. Release v0.2.0: podpisany tag na głowie PR-a, potem merge **commitem scalającym** (nie squash) — jeden deploy z `main` publikuje obie wersje. `workflow_dispatch` zostaje jako ponowny deploy | środowisko `github-pages` przyjmuje deploy wyłącznie z gałęzi `main` (polityka gałęzi), więc deploy z wypchnięcia taga byłby odrzucony; bez taga `v0.1.0` build z tagów zdjąłby opublikowaną wersję |
| P12 | **Odstępstwo (jedyne dozwolone odłożenie):** produkcyjne `ALLOWED_PARENT_ORIGINS` w `src/config.js` zostaje takie jak dziś (`["http://127.0.0.1:8000"]`), a README dostaje wyraźne „TODO przed użyciem produkcyjnym: dopisać hosty panelu (nowy release)" | ruling zlecającego: hosty produkcyjne panelu nie są ustalone (spec, „Nie ustalono"). Odstępstwo od rozstrzygnięcia 11 — wersja 0.2.0 nie nadaje się do użycia klinicznego, co i tak wynika z `KEYVAULT_BROWSER_CLINICS_ENABLED=False` |
| P13 | Playwright używa dwóch skryptów testowych wstrzykiwanych przez `context.addInitScript` (działają też w ramkach cross-origin): zdejmowanie `prf.results` z wyniku `create()` (P-2) i przesuwalny `Date.now()` (P-3). Kod sejfu nie jest podmieniany | wirtualny authenticator CDP zawsze zwraca PRF przy `create()`; limit sesji wymaga upływu czasu (okno 5 min) |
| P14 | `sejf_v1.json` ma dokładnie klucze z kontraktu B2 (zadanie 10) plus pole testowe `prf_output` w każdym poświadczeniu i `note` w korzeniu | samosprawdzenie F1–F4 w sejfie wymaga podstawionego wyniku PRF; B2 czyta wyłącznie swoje klucze |
| P15 | Tekst jawny pola, który nie jest UTF-8 albo JSON-em → `bad_blob` (per element); `clinic_wrap`, który się nie otwiera → `decrypt_failed` dla elementów tego wywiadu (`bad_blob`, gdy długość ≠ 113 B) | tabela kodów błędów nie ma osobnych kodów |
| P16 | `rpId = location.hostname` (produkcyjnie `bobik-2.github.io`, w E2E `localhost`) | WebAuthn i tak odrzuca RP ID spoza originu strony; brak drugiego miejsca konfiguracji |

## Global Constraints

- **Repo i gałąź:** worktree `/Volumes/SSD/Programowanie/bobik-sejf-feat-b1`, gałąź `feat/b1-protokol-krypto` (z `main` @ `f690d3a`). Wszystkie ścieżki w planie są względne wobec tego katalogu. Klonu `/Volumes/SSD/Programowanie/bobik-sejf` **nie modyfikuj** (jedyny dozwolony odczyt: `.git/allowed_signers` w zadaniu 11).
- **Narzędzia:** Node ≥ 24 (CI: 24, lokalnie 26.8.1), `npm ci`. Zależności dev dokładnie: `@hpke/core` 1.9.0, `@hpke/common` 1.10.1, `vitest` 5.0.5, `@playwright/test` 1.64.1. Przeglądarki Playwright 1.64.1 (`chromium-1248`, `firefox-1555`, `webkit-2370`) są w `~/Library/Caches/ms-playwright` (stan 2026-10-25); jeśli `npx playwright test` zgłosi brak, `npx playwright install chromium firefox webkit`.
- **Bez bundlera i bez zależności runtime** poza `src/vendor/`. Kod publikowany = moduły ES w `src/`.
- **CSP sejfu** (`src/index.html`, bez zmian): `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'`. W `src/*.html` zero `<script>` bez `src`, zero atrybutów `on…=`, zero `style=`. Teksty od panelu (etykiety, `study_code`) wyłącznie przez `textContent` — nigdy `innerHTML`/`outerHTML`/`insertAdjacentHTML`.
- **Origin i RP ID:** `https://bobik-2.github.io` / `bobik-2.github.io`, ustalone na zawsze; w kodzie `rpId = location.hostname` (P16).
- **Koperta (bez zmian):** żądanie `{v: 1, id: "<1–64 znaki>", op, ...argumenty}`, odpowiedź `{v: 1, id, ok: true, result}` | `{v: 1, id, ok: false, error: "<kod>"}`, zdarzenie `{v: 1, event: "locked", reason: "user"|"idle"|"limit"|"max_age"}`. Odpowiedź zawsze `postMessage(resp, event.origin)`, nigdy `"*"`.
- **Kody błędów (wyłącznie te):** `bad_message`, `bad_version`, `bad_id`, `bad_op`, `unknown_op`, `bad_args`, `busy`, `revoked`, `browser_blocked`, `locked`, `rate_limited`, `limit_reached`, `user_rejected`, `unwrap_failed`, `clinic_key_not_loaded`, `unknown_interview`, `key_mismatch`, `bad_blob`, `decrypt_failed`, `bad_key`, `bad_lease_key`, `internal` oraz WebAuthn: `not_allowed`, `already_registered`, `bad_rp_id`, `webauthn_failed`, `not_security_key`, `no_prf`, `no_keys`, `unknown_credential`.
- **Konteksty (dosłownie):** `bobik/doctor-kek/v1|doctor=<doctor_id>|credential=<credential>`; `bobik/doctor-wrap/v1|doctor=<doctor_id>|credential=<credential>|doctor_spki_sha256=<hex>`; `bobik/clinic-grant/v1|clinic=<clinic_id>|doctor=<doctor_id>|clinic_spki_sha256=<hex>`; `bobik/dek/v1|interview=<interview_id>`; AAD `Sealed` = nagłówek(17 B) ‖ `"|interview=<interview_id>|field=<etykieta>"`; `info` STC = `"bobik/stc/v1|"` ‖ nagłówek(17 B) ‖ `"|clinic=<clinic_id>|field=<etykieta>"`. `<credential>` = `rawId` w base64url bez paddingu, `<hex>` = SHA-256 SPKI DER, 64 znaki małymi literami.
- **Formaty bajtów:** F3 `[0x01][iv 12 B][ct ‖ tag 16 B]`; F4 `[0x01][enc 65 B][ct ‖ tag]`; `Sealed` `[0x01][InterviewKey.id 16 B][nonce 12 B][ct ‖ tag]`; `SealedToClinic` `[0x02][ClinicKey.id 16 B][enc 65 B][ct ‖ tag]`; `clinic_wrap` = 65 + 32 + 16 = 113 B; F6 = 384 B (RSA-OAEP, SHA-256, MGF1-SHA-256, etykieta pusta, moduł 3072, `e = 65537`). Bajty w JSON: base64url bez paddingu (F8).
- **HPKE:** RFC 9180, tryb base, DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, AAD puste, kontekst w `info`. Otwieranie **zawsze** `CryptoKeyPair` `{privateKey (extractable: false), publicKey}` (spike: sam klucz prywatny działa dla ok. połowy kluczy).
- **Limity (`src/limits.js`, dosłownie):** 50 wywiadów na odblokowanie (dalej auto-blokada `limit`), 10 nowych wywiadów w oknie 5 min (`rate_limited`), 500 wartości `SealedToClinic` na odblokowanie (auto-blokada), 100 wartości STC na minutę (`rate_limited`), bezczynność 15 min (`idle`), wiek odblokowania 8 h (`max_age`). `open` ≤ 1000 elementów.
- **WebAuthn:** `userVerification: "required"` przy `create()` i `get()` (rozstrzygnięcie 6); tylko klucze sprzętowe (istniejące odrzucanie `platform`/`internal`/`hybrid` zostaje).
- **Klucze:** prywatne klucze lekarza i kliniki oraz DEK w pamięci wyłącznie jako `CryptoKey` z `extractable: false`. Wyjątki: para przy `register` (P1) i chwilowa kopia przy `add_credential` (F3). Bufory PKCS8 kliniki, DEK i wynik PRF zerowane `fill(0)` zaraz po użyciu (rozstrzygnięcie 14). Nic nie trafia do `localStorage`/IndexedDB (rozstrzygnięcie 13).
- **HARD-FAIL:** żadnego `catch` „na wszelki wypadek". Każdy `catch (e)` sprawdza wąski typ (`e instanceof …` albo `e?.name === "OperationError"` itp.), zamienia go na `VaultError(<kod>)` z komentarzem dlaczego ten typ pada w tym miejscu, a wszystko inne rzuca dalej. Nieprzewidziany wyjątek → kod `internal`, a w konsoli wyłącznie `e.name`, bez treści. Istniejący fail-closed `fetchRevoked` zostaje bez zmian, nowych takich miejsc nie dodawaj.
- **Język:** UI, komentarze, nazwy testów i komunikaty commitów po polsku.
- **Commity:** podpisywane automatycznie (`commit.gpgsign=true`, SSH) — nigdy `--no-gpg-sign`. Każdy commit kończy się:
  ```
  Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
  Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk
  ```
- **Obciążenie maszyny:** przed każdym przebiegiem Playwright i przed pełnym `npx vitest run`:
  ```bash
  uptime; docker ps --format '{{.Names}}\t{{.Status}}'; docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'
  ```
  Load (1 min) ≥ ~8 albo aktywny cudzy przebieg testów → czekaj (sprawdzaj co 10–20 min), nie odpalaj „na próbę".
- **Działania na zewnątrz** (wypchnięcie taga, gałęzi, PR, merge, `gh workflow run`) wyłącznie za zgodą użytkownika — kroki oznaczone **[zgoda użytkownika]**.

## Review Focus

1. **Blokada w trakcie operacji.** Panel (albo przycisk „Zablokuj", bezczynność, limit) blokuje sejf, gdy `unlock`, `grant_lease` albo `open` jeszcze trwa. Oczekiwane: operacja kończy się `locked`, nie zwraca wyniku policzonego starymi kluczami i nie zostawia kluczy w nowej sesji. Testy: zadanie 7 (`unlock`/`register` z wiszącym potwierdzeniem + `lock`), zadanie 8 (`grant_lease` z wiszącym potwierdzeniem + `lock` → brak `rsa_wrapped_dek`).
2. **Etykiety od panelu jako HTML.** `clinic_label`/`recipient_label`/`study_code` zawierające `<img onerror=…>` muszą się pokazać dosłownie, bez wykonania na originie sejfu. Testy: zadanie 9 (statyczny zakaz `innerHTML` & co. w `src/`), zadanie 10 (P-1: etykieta z HTML widoczna jako tekst, brak `<img>` w ramce).
3. **Ten sam wywiad dwa razy albo z innym kluczem.** Powtórzony `interview_id` w jednym `open`, ponowne otwarcie z innym `interview_key_id` niż w pamięci, element `sealed` bez wpisu w `interviews`. Oczekiwane: `bad_args` / ponowne odpakowanie i `key_mismatch` dla starych blobów / `unknown_interview`, a licznik wywiadów rośnie raz. Testy: zadanie 8.
4. **Wiadomość, która wygląda na panel.** Dozwolony `event.origin`, ale `event.source` nie jest rodzicem (np. popup), `ancestorOrigins[0]` inny niż `event.origin`, `ancestorOrigins[0] === "null"`, `event.origin === "null"`, sejf otwarty jako strona najwyższego poziomu. Testy: zadanie 9 (`parent.test.js` + E2E strony najwyższego poziomu i obcego originu).
5. **Build, który cicho publikuje coś innego.** Tag bez podpisu, tag spoza historii `HEAD`, zmieniony `src/` wydanej wersji, nieaktualny `releases/<X>.sha256`, brak tagów w ogóle. Oczekiwane: build pada z komunikatem, nie pomija wersji. Testy: zadanie 11 (`build.test.js` na tymczasowym repo z kluczem SSH).

---

## Mapa plików

| Plik | Odpowiedzialność | Zadanie |
|---|---|---|
| `package.json`, `package-lock.json` | `@hpke/common` 1.10.1 jawnie; skrypty `vendor`, `vectors`; wersja 0.2.0 | 1, 12 |
| `scripts/sums.mjs` (nowy) | `walk`, `sumsOf(dir)` — format `SHA256SUMS` | 1 |
| `scripts/vendor-hpke.mjs` (nowy), `src/vendor/hpke-core-1.9.0/`, `src/vendor/hpke-common-1.10.1/`, `src/vendor/SHA256SUMS` | wendorowanie HPKE | 1 |
| `src/bytes.js` (nowy) | `utf8`, `concat`, `hex`, `sha256Hex`, `bytesToUuid`, `random` | 1 |
| `src/crypto/hpke.js` (nowy) | `hpkeSeal`, `hpkeOpen`, `isHpkeFailure`, `ENC_LEN` | 1 |
| `src/errors.js` (nowy) | `VaultError`, `codeOf` | 2 |
| `src/crypto/context.js` (nowy) | konteksty F2–F5 | 2 |
| `src/crypto/keys.js` (nowy) | `importP256Public`, `importP256Pair` | 2 |
| `src/crypto/fields.js` (nowy) | F5: `openClinicWrap`, `importDek`, `openSealed`, `openStc`, `sealedKeyId`, `stcKeyId` | 2 |
| `test/vectors/bobik2_v1.json`, `test/vectors/SHA256SUMS`, `test/helpers/vectors.js` | wektory serwera + pomocnicy | 2 |
| `src/crypto/doctor.js` (nowy) | F1–F3: `deriveKek`, `generateDoctorKey`, `wrapDoctorKey`, `unwrapDoctorKey` | 3 |
| `src/crypto/clinic.js` (nowy) | F4: `generateClinicKey`, `sealClinicGrant`, `openClinicGrant` | 3 |
| `src/crypto/lease.js` (nowy) | F6: `importLeaseKey`, `wrapDekForLease` | 4 |
| `scripts/gen-vectors.mjs` (nowy), `test/vectors/sejf_v1.json` | wektory sejfu | 4 |
| `src/b64.js`, `src/webauthn.js` | `B64Error`, ścisłe dekodowanie; `userVerification: "required"` | 5 |
| `test/helpers/fake-webauthn.js` (nowy) | atrapa `navigator.credentials` z PRF | 5 |
| `src/limits.js`, `src/validate.js`, `src/prompts.js` (nowe) | limit z zegarem wstrzykiwanym; walidatory `bad_args`; teksty UI i potwierdzeń | 6 |
| `src/session.js`, `src/core.js`, `src/ops/index.js`, `src/ops/basic.js`, `src/ops/doctor.js` (nowe) | rdzeń, `hello`, `lock`, `register`, `unlock`, `add_credential` | 7 |
| `test/helpers/fake-ui.js`, `test/helpers/vault.js` (nowe) | atrapa UI i fabryka sejfu do testów | 7 |
| `src/ops/clinic.js`, `src/ops/open.js`, `src/ops/lease.js` (nowe) | `load_clinic_key`, `create_clinic_key`, `grant_clinic_access`, `open`, `grant_lease` | 8 |
| `src/parent.js`, `src/ui.js` (nowe), `src/vault.js`, `src/index.html`, `src/vault.css`, `src/config.js` | przeglądarka: filtr rodzica, UI, spięcie; `VERSION = "0.2.0"`, znaczniki originów | 9 |
| `scripts/dev-config.mjs` (nowy), `scripts/serve.mjs` | podmiana originów dla dev/E2E | 9 |
| `playwright.config.js`, `test/e2e/panel/*`, `test/e2e/helpers.js`, `test/e2e/protocol.spec.js`, `test/e2e/demo.spec.js` (usuwany `test/e2e/hello.spec.js`) | E2E protokołu, P-4, P-5 | 9 |
| `test/e2e/flows.spec.js`, `test/e2e/limits.spec.js`, `test/e2e/shims.js` (nowe) | P-1, P-2, P-3 | 10 |
| `scripts/release-lib.mjs`, `scripts/release-sums.mjs` (nowe), `scripts/build.mjs`, `releases/allowed_signers`, `releases/0.1.0.sha256`, `.github/workflows/ci.yml` | build z tagów | 11 |
| `public/revoked.json`, `public/index.html`, `README.md`, `releases/0.2.0.sha256` | release v0.2.0 | 12 |

---

## Zadanie 1: Wendorowanie `@hpke/core` i moduł HPKE sejfu

**Files:**
- Modify: `package.json`, `package-lock.json` (`@hpke/common` 1.10.1 jawnie, skrypt `vendor`)
- Create: `scripts/sums.mjs`, `scripts/vendor-hpke.mjs`, `src/vendor/` (generowany), `src/bytes.js`, `src/crypto/hpke.js`
- Test: `test/unit/vendor.test.js`, `test/unit/bytes.test.js`, `test/unit/hpke.test.js`

**Interfaces:**
- Produces:
  - `scripts/sums.mjs`: `walk(dir) → Promise<string[]>`, `sumsOf(dir, {exclude = []}) → Promise<string>` (linie `"<sha256>  <ścieżka POSIX>"`, posortowane po ścieżce, `\n` na końcu).
  - `src/bytes.js`: `utf8(text) → Uint8Array`, `concat(...Uint8Array) → Uint8Array`, `hex(bytes) → string`, `sha256Hex(bytes) → Promise<string>`, `bytesToUuid(bytes16) → string` (inna długość → `RangeError`), `random(n) → Uint8Array`.
  - `src/crypto/hpke.js`: `ENC_LEN = 65`, `hpkeSeal(recipientPublicKey: CryptoKey, info: Uint8Array, plaintext: Uint8Array) → Promise<Uint8Array>` (enc ‖ ct), `hpkeOpen(recipientPair: {privateKey, publicKey}, info, blob) → Promise<Uint8Array>`, `isHpkeFailure(e) → boolean`.

- [ ] **Krok 1: Instalacja zależności w worktree i przypięcie `@hpke/common`**

Worktree nie ma `node_modules` (to, co widać w `../bobik-sejf`, należy do innego klonu).

```bash
cd /Volumes/SSD/Programowanie/bobik-sejf-feat-b1
npm ci
npm install --save-dev --save-exact @hpke/common@1.10.1
node -e "const p=require('./package.json'); console.log(p.devDependencies)"
```

Expected: `{ '@hpke/common': '1.10.1', '@hpke/core': '1.9.0', '@playwright/test': '1.64.1', vitest: '5.0.5' }`. Następnie dopisz w `package.json` do `"scripts"`:

```json
    "vendor": "node scripts/vendor-hpke.mjs",
```

Punkt odniesienia (wszystko zielone przed zmianami):

```bash
npx vitest run
```

Expected: PASS (5 plików: b64, demo-store, fingerprint, protocol, webauthn).

- [ ] **Krok 2: Testy, które mają paść**

`test/unit/bytes.test.js`:

```js
import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { bytesToUuid, concat, hex, random, sha256Hex, utf8 } from "../../src/bytes.js";

it("concat, hex, utf8", () => {
  expect(concat(Uint8Array.of(1), Uint8Array.of(2, 255))).toEqual(Uint8Array.of(1, 2, 255));
  expect(hex(Uint8Array.of(0, 15, 255))).toBe("000fff");
  expect(utf8("ż")).toEqual(Uint8Array.of(0xc5, 0xbc));
});

it("sha256Hex = SHA-256, 64 znaki hex małymi literami", async () => {
  const data = utf8("abc");
  expect(await sha256Hex(data)).toBe(createHash("sha256").update(data).digest("hex"));
});

it("bytesToUuid: 16 B -> UUID z myślnikami; inna długość -> RangeError", () => {
  const bytes = Uint8Array.from("66666666777748889999aaaaaaaaaaaa".match(/../g), (h) => parseInt(h, 16));
  expect(bytesToUuid(bytes)).toBe("66666666-7777-4888-9999-aaaaaaaaaaaa");
  expect(() => bytesToUuid(new Uint8Array(15))).toThrow(RangeError);
});

it("random(n) daje n losowych bajtów", () => {
  expect(random(32)).toHaveLength(32);
  expect(random(32)).not.toEqual(random(32));
});
```

`test/unit/hpke.test.js`:

```js
import { expect, it } from "vitest";
import { utf8 } from "../../src/bytes.js";
import { ENC_LEN, hpkeOpen, hpkeSeal, isHpkeFailure } from "../../src/crypto/hpke.js";

const P256 = { name: "ECDH", namedCurve: "P-256" };

// Para jak w sejfie: prywatny nieeksportowalny, publiczny obok (spike, pułapka znaku y).
async function pair() {
  const g = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", g.privateKey);
  const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, P256, false, ["deriveBits"]);
  return { privateKey, publicKey: g.publicKey };
}

it("seal/open parą z nieeksportowalnym kluczem prywatnym działa dla 8 świeżych kluczy (oba znaki y)", async () => {
  for (let i = 0; i < 8; i++) {
    const p = await pair();
    const blob = await hpkeSeal(p.publicKey, utf8("info"), utf8("tresc"));
    expect(blob).toHaveLength(ENC_LEN + 5 + 16);
    expect(new TextDecoder().decode(await hpkeOpen(p, utf8("info"), blob))).toBe("tresc");
  }
});

it("inny info -> błąd rozpoznawany przez isHpkeFailure", async () => {
  const p = await pair();
  const blob = await hpkeSeal(p.publicKey, utf8("a"), utf8("x"));
  const err = await hpkeOpen(p, utf8("b"), blob).catch((e) => e);
  expect(isHpkeFailure(err)).toBe(true);
});

it("zwykły wyjątek nie jest błędem HPKE", () => {
  expect(isHpkeFailure(new TypeError("x"))).toBe(false);
});
```

`test/unit/vendor.test.js`:

```js
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { expect, it } from "vitest";
import { sumsOf, walk } from "../../scripts/sums.mjs";

const VENDOR = "src/vendor";

it("SHA256SUMS opisuje dokładnie pliki w src/vendor", async () => {
  expect(await sumsOf(VENDOR, { exclude: ["SHA256SUMS"] })).toBe(readFileSync(join(VENDOR, "SHA256SUMS"), "utf8"));
});

it("importy statyczne bez gołych specyfikatorów (CSP: bez import map)", async () => {
  const offenders = [];
  for (const file of (await walk(VENDOR)).filter((f) => f.endsWith(".js"))) {
    readFileSync(file, "utf8").split("\n").forEach((line, i) => {
      if (/^\s*(\*|\/\/)/.test(line)) return; // przykłady w JSDoc
      if (/\bfrom\s+["'](?![./])/.test(line)) offenders.push(`${file}:${i + 1}`);
    });
  }
  expect(offenders).toEqual([]);
});

it("src/vendor = node_modules w przypiętych wersjach (regeneracja daje te same sumy)", () => {
  const tmp = mkdtempSync(join(tmpdir(), "sejf-vendor-"));
  execFileSync("node", ["scripts/vendor-hpke.mjs", tmp]);
  expect(readFileSync(join(tmp, "SHA256SUMS"), "utf8")).toBe(readFileSync(join(VENDOR, "SHA256SUMS"), "utf8"));
}, 30_000);

it("moduł ładuje się ścieżką względną", async () => {
  const mod = await import("../../src/vendor/hpke-core-1.9.0/mod.js");
  expect(typeof mod.CipherSuite).toBe("function");
});
```

- [ ] **Krok 3: Uruchom — mają paść**

Run: `npx vitest run test/unit/bytes.test.js test/unit/hpke.test.js test/unit/vendor.test.js`
Expected: FAIL (`Cannot find module '../../src/bytes.js'`, `../../scripts/sums.mjs`, `src/vendor` nie istnieje).

- [ ] **Krok 4: `scripts/sums.mjs`**

```js
// SHA256SUMS: „<sha256>  <ścieżka>" na linię; ścieżki POSIX względne wobec katalogu, posortowane.
import { createHash } from "node:crypto";
import { readdir, readFile } from "node:fs/promises";
import { join, relative, sep } from "node:path";

export async function walk(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...(await walk(path)));
    else out.push(path);
  }
  return out;
}

export async function sumsOf(dir, { exclude = [] } = {}) {
  const paths = (await walk(dir))
    .map((f) => relative(dir, f).split(sep).join("/"))
    .filter((p) => !exclude.includes(p))
    .sort();
  const lines = [];
  for (const p of paths) {
    lines.push(`${createHash("sha256").update(await readFile(join(dir, p))).digest("hex")}  ${p}`);
  }
  return `${lines.join("\n")}\n`;
}
```

- [ ] **Krok 5: `scripts/vendor-hpke.mjs` i wygenerowanie `src/vendor/`**

```js
// Wendoruje @hpke/core i @hpke/common z node_modules do src/vendor/ (bez bundlera).
// `from "@hpke/common"` przepisuje na ścieżki względne: import map inline łamie CSP
// `script-src 'self'` (spike). Treść plików poza tym jest 1:1 z paczek npm.
// Użycie: node scripts/vendor-hpke.mjs [katalog=src/vendor]
import { copyFile, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join, posix, relative, sep } from "node:path";
import { sumsOf, walk } from "./sums.mjs";

const PACKAGES = [
  { name: "@hpke/common", version: "1.10.1", dir: "hpke-common-1.10.1" },
  { name: "@hpke/core", version: "1.9.0", dir: "hpke-core-1.9.0" },
];
const COMMON_ENTRY = "hpke-common-1.10.1/mod.js";
const out = process.argv[2] ?? "src/vendor";

await rm(out, { recursive: true, force: true });
for (const pkg of PACKAGES) {
  const root = join("node_modules", ...pkg.name.split("/"));
  const { version } = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  if (version !== pkg.version) {
    throw new Error(`${pkg.name}: w node_modules jest ${version}, oczekiwano ${pkg.version} (uruchom npm ci)`);
  }
  const esm = join(root, "esm");
  for (const file of (await walk(esm)).filter((f) => f.endsWith(".js")).sort()) {
    const target = posix.join(pkg.dir, relative(esm, file).split(sep).join("/"));
    let spec = posix.relative(posix.dirname(target), COMMON_ENTRY);
    if (!spec.startsWith(".")) spec = `./${spec}`;
    const text = (await readFile(file, "utf8")).replaceAll('from "@hpke/common"', `from "${spec}"`);
    await mkdir(dirname(join(out, target)), { recursive: true });
    await writeFile(join(out, target), text);
  }
  await copyFile(join(root, "LICENSE"), join(out, pkg.dir, "LICENSE"));
}
await writeFile(join(out, "SHA256SUMS"), await sumsOf(out, { exclude: ["SHA256SUMS"] }));
console.log(`${out}: ${PACKAGES.map((p) => `${p.name}@${p.version}`).join(", ")}`);
```

```bash
node scripts/vendor-hpke.mjs
find src/vendor -type f | wc -l
grep -rn 'hpke-common-1.10.1/mod.js' src/vendor/hpke-core-1.9.0/mod.js src/vendor/hpke-core-1.9.0/src/kems/dhkemNative.js
```

Expected: ok. 61 plików (58 `.js` + 2 × `LICENSE` + `SHA256SUMS`); `mod.js` importuje `"../hpke-common-1.10.1/mod.js"`, a `src/kems/dhkemNative.js` `"../../../hpke-common-1.10.1/mod.js"`. Dynamiczne `import("crypto")` w `@hpke/common` zostaje: wykonuje się wyłącznie, gdy brak `globalThis.crypto` (Node ≤ 18), czyli nigdy w przeglądarce.

- [ ] **Krok 6: `src/bytes.js`**

```js
// Operacje na bajtach wspólne dla modułów kryptograficznych sejfu.

export const utf8 = (text) => new TextEncoder().encode(text);

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

export const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export async function sha256Hex(bytes) {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

// UUID z 16 bajtów nagłówka koperty (InterviewKey.id / ClinicKey.id), postać jak str(uuid) w Pythonie.
export function bytesToUuid(bytes) {
  if (bytes.length !== 16) throw new RangeError(`UUID: oczekiwano 16 B, jest ${bytes.length}`);
  const h = hex(bytes);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export const random = (n) => crypto.getRandomValues(new Uint8Array(n));
```

- [ ] **Krok 7: `src/crypto/hpke.js`**

```js
// HPKE (RFC 9180, tryb base, single-shot): DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM,
// AAD puste, kontekst w `info` (handoff, sekcja 4). Wynik: enc (65 B) ‖ szyfrogram ‖ tag.
import {
  Aes256Gcm,
  CipherSuite,
  DecapError,
  DeserializeError,
  DhkemP256HkdfSha256,
  HkdfSha256,
  OpenError,
  ValidationError,
} from "../vendor/hpke-core-1.9.0/mod.js";
import { concat } from "../bytes.js";

export const ENC_LEN = 65;

const suite = new CipherSuite({ kem: new DhkemP256HkdfSha256(), kdf: new HkdfSha256(), aead: new Aes256Gcm() });

export async function hpkeSeal(recipientPublicKey, info, plaintext) {
  const { ct, enc } = await suite.seal({ recipientPublicKey, info }, plaintext);
  return concat(new Uint8Array(enc), new Uint8Array(ct));
}

// `recipientPair` MUSI być parą {privateKey, publicKey}: z samym nieeksportowalnym kluczem
// prywatnym @hpke/common zgaduje znak y klucza publicznego i myli się dla ok. połowy kluczy (spike).
export async function hpkeOpen(recipientPair, info, blob) {
  const plaintext = await suite.open({ recipientKey: recipientPair, enc: blob.slice(0, ENC_LEN), info }, blob.slice(ENC_LEN));
  return new Uint8Array(plaintext);
}

// Wyjątki, którymi @hpke/core kończy nieudane otwarcie: zły klucz, kontekst, enc albo szyfrogram.
export function isHpkeFailure(e) {
  return e instanceof OpenError || e instanceof DecapError || e instanceof DeserializeError || e instanceof ValidationError;
}
```

- [ ] **Krok 8: Uruchom — mają przejść**

Run: `npx vitest run`
Expected: PASS (wszystkie pliki, w tym 3 nowe).

- [ ] **Krok 9: Commit**

```bash
git add package.json package-lock.json scripts/sums.mjs scripts/vendor-hpke.mjs src/vendor src/bytes.js src/crypto/hpke.js test/unit/bytes.test.js test/unit/hpke.test.js test/unit/vendor.test.js
git commit -m "feat(krypto): wendorowane @hpke/core 1.9.0 + @hpke/common 1.10.1 i moduł HPKE sejfu

Importy @hpke/common przepisane na ścieżki względne (CSP script-src 'self' bez
import map), sumy w src/vendor/SHA256SUMS, test regeneracji z node_modules.
hpkeOpen przyjmuje wyłącznie parę kluczy (pułapka znaku y ze spike'a).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 2: Wektory `bobik2_v1.json`, konteksty i pola F5 (V-1, część serwerowa)

**Files:**
- Create: `test/vectors/bobik2_v1.json` (kopia z bobik-2), `test/vectors/SHA256SUMS`, `test/helpers/vectors.js`, `src/errors.js`, `src/crypto/context.js`, `src/crypto/keys.js`, `src/crypto/fields.js`
- Test: `test/unit/vectors.test.js`, `test/unit/errors.test.js`, `test/unit/context.test.js`, `test/unit/keys.test.js`, `test/unit/fields.test.js`

**Interfaces:**
- Consumes: `src/bytes.js`, `src/crypto/hpke.js` (zadanie 1), istniejące `src/protocol.js::ProtocolError`, `src/webauthn.js::WebAuthnError`, `src/fingerprint.js::fingerprint`, `src/b64.js::fromB64url`.
- Produces:
  - `src/errors.js`: `class VaultError extends Error {code}`, `codeOf(e, log = console) → string` (kod z `VaultError`/`ProtocolError`/`WebAuthnError`; inne → `"internal"` i `log.error("sejf: nieprzewidziany błąd", e?.name ?? typeof e)`).
  - `src/crypto/context.js`: `doctorKekInfo(doctorId, credential)`, `doctorWrapAad(doctorId, credential, spkiHex)`, `clinicGrantInfo(clinicId, doctorId, clinicSpkiHex)`, `dekInfo(interviewId)`, `sealedContext(interviewId, field)`, `stcContext(clinicId, field)`, `STC_INFO_PREFIX` — wszystkie zwracają `string`.
  - `src/crypto/keys.js`: `importP256Public(spki) → Promise<CryptoKey>` (`bad_key`), `importP256Pair(pkcs8, publicKey) → Promise<{privateKey, publicKey}>` (zeruje `pkcs8`; zły PKCS8 → `unwrap_failed`).
  - `src/crypto/fields.js`: `CLINIC_WRAP_LEN = 113`, `openClinicWrap(clinicPair, interviewId, blob) → Promise<Uint8Array>` (DEK 32 B; `bad_blob`/`decrypt_failed`), `importDek(raw) → Promise<CryptoKey>` (zeruje `raw`), `sealedKeyId(blob) → string`, `openSealed(dekKey, {interviewId, interviewKeyId, field, blob}) → Promise<any>`, `stcKeyId(blob) → string`, `openStc(clinicPair, {clinicId, field, blob}) → Promise<any>`; błędy jako `VaultError` z kodami `bad_blob`, `key_mismatch`, `decrypt_failed`.
  - `test/helpers/vectors.js`: `BOBIK2`, `loadSejf()`, `b(text)`, `bobik2ClinicPair()`, `bobik2Interview()`, `bobik2OpenRequest()`, `bobik2ExpectedValues()`, `bobik2LeaseArgs(overrides)`.

- [ ] **Krok 1: Kopia wektorów z bobik-2 i suma**

```bash
cp /Volumes/SSD/Programowanie/bobik-2/src/bobik2/crypto/tests/vectors/bobik2_v1.json test/vectors/bobik2_v1.json
(cd test/vectors && shasum -a 256 bobik2_v1.json > SHA256SUMS && cat SHA256SUMS)
grep bobik2_v1.json /Volumes/SSD/Programowanie/bobik-2/src/bobik2/crypto/tests/vectors/SHA256SUMS
```

Expected: obie linie identyczne: `f9ca1b3c31633e85c4648305e1cc0057927074cf2cbf6254d91ca5bd670ece50  bobik2_v1.json`. Inna suma = bobik-2 zmienił wektory; zatrzymaj się i zgłoś (test niżej pinuje tę sumę).

- [ ] **Krok 2: Pomocnik `test/helpers/vectors.js`**

```js
// Wektory krzyżowe (spec B, „Wektory krzyżowe"): odczyt i gotowe argumenty protokołu.
// Używany przez Vitest i przez testy Playwright (proces Node).
import { readFileSync } from "node:fs";
import { fromB64url } from "../../src/b64.js";

const load = (name) => JSON.parse(readFileSync(new URL(`../vectors/${name}`, import.meta.url), "utf8"));

export const BOBIK2 = load("bobik2_v1.json");
export const loadSejf = () => load("sejf_v1.json");
export const b = (text) => fromB64url(text);

const P256 = { name: "ECDH", namedCurve: "P-256" };

export async function bobik2ClinicPair() {
  return {
    privateKey: await crypto.subtle.importKey("pkcs8", b(BOBIK2.clinic.private_key_pkcs8_der), P256, false, ["deriveBits"]),
    publicKey: await crypto.subtle.importKey("spki", b(BOBIK2.clinic.public_key_spki_der), P256, true, []),
  };
}

export function bobik2Interview() {
  return {
    interview_id: BOBIK2.interview_id,
    interview_key_id: BOBIK2.interview_key_id,
    clinic_key_id: BOBIK2.clinic_key_id,
    clinic_wrap: BOBIK2.clinic_wrap.blob,
  };
}

// Argumenty `open`: wszystkie pola z wektora, potem przypadki negatywne (kolejność = bobik2ExpectedValues).
export function bobik2OpenRequest() {
  const sealed = BOBIK2.sealed.map((s) => ({ kind: "sealed", interview_id: BOBIK2.interview_id, field: s.field, blob: s.blob }));
  const stc = BOBIK2.stc.map((s) => ({ kind: "stc", clinic_id: BOBIK2.clinic_id, field: s.field, blob: s.blob }));
  const negative = BOBIK2.negative.map((n) =>
    n.kind === "sealed"
      ? { kind: "sealed", interview_id: n.interview_id, field: n.field, blob: n.blob }
      : { kind: "stc", clinic_id: n.clinic_id, field: n.field, blob: n.blob },
  );
  return { interviews: [bobik2Interview()], items: [...sealed, ...stc, ...negative] };
}

export function bobik2ExpectedValues() {
  return [
    ...BOBIK2.sealed.map((s) => ({ ok: true, value: s.value })),
    ...BOBIK2.stc.map((s) => ({ ok: true, value: s.value })),
    ...BOBIK2.negative.map((n) => ({ ok: false, error: n.error })),
  ];
}

export function bobik2LeaseArgs(overrides = {}) {
  return {
    ...bobik2Interview(),
    study_code: "BOB-0001",
    kind: "addendum",
    session_seq: null,
    agent_run_id: null,
    lease_public_key_der: BOBIK2.rsa_lease_key.public_key_spki_der,
    ...overrides,
  };
}
```

- [ ] **Krok 3: Testy, które mają paść**

`test/unit/vectors.test.js`:

```js
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { fingerprint } from "../../src/fingerprint.js";
import { BOBIK2, b } from "../helpers/vectors.js";

const DIR = new URL("../vectors/", import.meta.url);
const sums = readFileSync(new URL("SHA256SUMS", DIR), "utf8").trim().split("\n").map((line) => line.split("  "));

it("SHA256SUMS: każdy wektor ma zapisaną sumę", () => {
  for (const [sum, name] of sums) {
    expect(createHash("sha256").update(readFileSync(new URL(name, DIR))).digest("hex"), name).toBe(sum);
  }
});

it("bobik2_v1.json to kopia 1:1 z bobik-2 (suma z SHA256SUMS bobik-2)", () => {
  expect(Object.fromEntries(sums.map(([s, n]) => [n, s]))["bobik2_v1.json"]).toBe(
    "f9ca1b3c31633e85c4648305e1cc0057927074cf2cbf6254d91ca5bd670ece50",
  );
});

it("F7: odciski liczone w sejfie = odciski z bobik-2 (bobik2.crypto.fingerprint)", async () => {
  expect(await fingerprint(b(BOBIK2.clinic.public_key_spki_der))).toBe(BOBIK2.clinic.fingerprint);
  expect(await fingerprint(b(BOBIK2.rsa_lease_key.public_key_spki_der))).toBe(BOBIK2.rsa_lease_key.fingerprint);
});
```

`test/unit/errors.test.js`:

```js
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
```

`test/unit/context.test.js`:

```js
import { expect, it } from "vitest";
import {
  clinicGrantInfo,
  dekInfo,
  doctorKekInfo,
  doctorWrapAad,
  sealedContext,
  STC_INFO_PREFIX,
  stcContext,
} from "../../src/crypto/context.js";
import { BOBIK2 } from "../helpers/vectors.js";

const HEX = "9b1c".padEnd(64, "0");
const IV = "3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b";

it("konteksty F2–F5 dosłownie jak w specu", () => {
  expect(doctorKekInfo(17, "q8Zr")).toBe("bobik/doctor-kek/v1|doctor=17|credential=q8Zr");
  expect(doctorWrapAad(17, "q8Zr", HEX)).toBe(`bobik/doctor-wrap/v1|doctor=17|credential=q8Zr|doctor_spki_sha256=${HEX}`);
  expect(clinicGrantInfo(3, 17, HEX)).toBe(`bobik/clinic-grant/v1|clinic=3|doctor=17|clinic_spki_sha256=${HEX}`);
  expect(sealedContext(IV, "interviews.Interview.age")).toBe(`interview=${IV}|field=interviews.Interview.age`);
  expect(stcContext(3, "core.WithdrawalLog.reason")).toBe("clinic=3|field=core.WithdrawalLog.reason");
  expect(STC_INFO_PREFIX).toBe("bobik/stc/v1|");
});

it("dekInfo zgodny z bobik-2 (keyvault.context.dek_info)", () => {
  expect(dekInfo(BOBIK2.interview_id)).toBe(BOBIK2.clinic_wrap.info);
});
```

`test/unit/keys.test.js`:

```js
import { expect, it } from "vitest";
import { importP256Pair, importP256Public } from "../../src/crypto/keys.js";
import { BOBIK2, b } from "../helpers/vectors.js";

it("importP256Public: SPKI P-256 kliniki z bobik-2", async () => {
  const key = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  expect(key.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });
});

it.each([
  ["RSA-3072", () => b(BOBIK2.rsa_lease_key.public_key_spki_der)],
  ["śmieci", () => new Uint8Array(91).fill(7)],
])("importP256Public: %s -> bad_key", async (_name, der) => {
  await expect(importP256Public(der())).rejects.toMatchObject({ code: "bad_key" });
});

it("importP256Pair: prywatny nieeksportowalny, publiczny obok, bufor PKCS8 wyzerowany", async () => {
  const pkcs8 = b(BOBIK2.clinic.private_key_pkcs8_der);
  const publicKey = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  const pair = await importP256Pair(pkcs8, publicKey);
  expect(pair.privateKey.extractable).toBe(false);
  expect(pair.publicKey).toBe(publicKey);
  expect(pkcs8.every((x) => x === 0)).toBe(true);
});

it("importP256Pair: PKCS8 nie-P-256 -> unwrap_failed, bufor i tak wyzerowany", async () => {
  const pkcs8 = b(BOBIK2.rsa_lease_key.private_key_pkcs8_der);
  const publicKey = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  await expect(importP256Pair(pkcs8, publicKey)).rejects.toMatchObject({ code: "unwrap_failed" });
  expect(pkcs8.every((x) => x === 0)).toBe(true);
});
```

`test/unit/fields.test.js`:

```js
import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { concat, utf8 } from "../../src/bytes.js";
import { sealedContext } from "../../src/crypto/context.js";
import { importDek, openClinicWrap, openSealed, openStc, sealedKeyId, stcKeyId } from "../../src/crypto/fields.js";
import { BOBIK2, b, bobik2ClinicPair } from "../helpers/vectors.js";

async function dekKey() {
  return importDek(await openClinicWrap(await bobik2ClinicPair(), BOBIK2.interview_id, b(BOBIK2.clinic_wrap.blob)));
}
const sealedArgs = (s) => ({ interviewId: BOBIK2.interview_id, interviewKeyId: BOBIK2.interview_key_id, field: s.field, blob: b(s.blob) });

describe("F5 z wektorami bobik2_v1.json (V-1)", () => {
  it("clinic_wrap otwiera się parą kliniki i daje DEK z wektora", async () => {
    const dek = await openClinicWrap(await bobik2ClinicPair(), BOBIK2.interview_id, b(BOBIK2.clinic_wrap.blob));
    expect(toB64url(dek)).toBe(BOBIK2.dek);
  });

  it("clinic_wrap z innym interview_id w info -> decrypt_failed", async () => {
    const other = "00000000-0000-4000-8000-000000000000";
    await expect(openClinicWrap(await bobik2ClinicPair(), other, b(BOBIK2.clinic_wrap.blob))).rejects.toMatchObject({ code: "decrypt_failed" });
  });

  it("clinic_wrap o złej długości -> bad_blob", async () => {
    const short = b(BOBIK2.clinic_wrap.blob).slice(1);
    await expect(openClinicWrap(await bobik2ClinicPair(), BOBIK2.interview_id, short)).rejects.toMatchObject({ code: "bad_blob" });
  });

  it.each(BOBIK2.sealed.map((s) => [s.field, s]))("Sealed %s", async (_field, s) => {
    expect(await openSealed(await dekKey(), sealedArgs(s))).toEqual(s.value);
  });

  it.each(BOBIK2.stc.map((s) => [s.field, s]))("SealedToClinic %s", async (_field, s) => {
    expect(stcKeyId(b(s.blob))).toBe(BOBIK2.clinic_key_id);
    expect(await openStc(await bobik2ClinicPair(), { clinicId: BOBIK2.clinic_id, field: s.field, blob: b(s.blob) })).toEqual(s.value);
  });

  it.each(BOBIK2.negative.map((n) => [n.case, n]))("przypadek negatywny %s -> kod z wektora", async (_case, n) => {
    const run =
      n.kind === "sealed"
        ? openSealed(await dekKey(), { interviewId: n.interview_id, interviewKeyId: BOBIK2.interview_key_id, field: n.field, blob: b(n.blob) })
        : openStc(await bobik2ClinicPair(), { clinicId: n.clinic_id, field: n.field, blob: b(n.blob) });
    await expect(run).rejects.toMatchObject({ code: n.error });
  });
});

describe("format kopert i bufory", () => {
  it("sealedKeyId czyta InterviewKey.id z nagłówka", () => {
    expect(sealedKeyId(b(BOBIK2.sealed[0].blob))).toBe(BOBIK2.interview_key_id);
  });

  it.each([
    ["zły bajt wersji", (x) => { x[0] = 0x02; return x; }],
    ["za krótki", (x) => x.slice(0, 40)],
  ])("Sealed: %s -> bad_blob", async (_name, mutate) => {
    const blob = mutate(b(BOBIK2.sealed[0].blob));
    await expect(openSealed(await dekKey(), { ...sealedArgs(BOBIK2.sealed[0]), blob })).rejects.toMatchObject({ code: "bad_blob" });
  });

  it("SealedToClinic: zły bajt wersji -> bad_blob", () => {
    const blob = b(BOBIK2.stc[0].blob);
    blob[0] = 0x01;
    expect(() => stcKeyId(blob)).toThrow(expect.objectContaining({ code: "bad_blob" }));
  });

  it("importDek: DEK nieeksportowalny, bufor wyzerowany", async () => {
    const raw = b(BOBIK2.dek);
    const key = await importDek(raw);
    expect(key.extractable).toBe(false);
    expect(raw.every((x) => x === 0)).toBe(true);
  });

  it("tekst jawny, który nie jest JSON-em -> bad_blob (P15)", async () => {
    const field = "interviews.Interview.first_name";
    const header = b(BOBIK2.sealed[0].blob).slice(0, 17);
    const nonce = new Uint8Array(12).fill(1);
    const enc = await crypto.subtle.importKey("raw", b(BOBIK2.dek), "AES-GCM", false, ["encrypt"]);
    const aad = concat(header, utf8(`|${sealedContext(BOBIK2.interview_id, field)}`));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: aad }, enc, utf8("nie-json")));
    const args = { interviewId: BOBIK2.interview_id, interviewKeyId: BOBIK2.interview_key_id, field, blob: concat(header, nonce, ct) };
    await expect(openSealed(await dekKey(), args)).rejects.toMatchObject({ code: "bad_blob" });
  });
});
```

- [ ] **Krok 4: Uruchom — mają paść**

Run: `npx vitest run test/unit/vectors.test.js test/unit/errors.test.js test/unit/context.test.js test/unit/keys.test.js test/unit/fields.test.js`
Expected: `vectors.test.js` PASS (plik już jest), pozostałe FAIL (`Cannot find module '../../src/errors.js'` itd.).

- [ ] **Krok 5: `src/errors.js`**

```js
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
```

- [ ] **Krok 6: `src/crypto/context.js`**

```js
// Konteksty wiążące szyfrogramy z miejscem użycia (spec B, „Formaty"; bobik-2 keyvault/context.py).
// Zmiana formatu = nowa wersja (/v2|, nowy bajt wersji), nigdy edycja istniejącego.

export const doctorKekInfo = (doctorId, credential) => `bobik/doctor-kek/v1|doctor=${doctorId}|credential=${credential}`;

export const doctorWrapAad = (doctorId, credential, spkiHex) =>
  `bobik/doctor-wrap/v1|doctor=${doctorId}|credential=${credential}|doctor_spki_sha256=${spkiHex}`;

export const clinicGrantInfo = (clinicId, doctorId, clinicSpkiHex) =>
  `bobik/clinic-grant/v1|clinic=${clinicId}|doctor=${doctorId}|clinic_spki_sha256=${clinicSpkiHex}`;

export const dekInfo = (interviewId) => `bobik/dek/v1|interview=${interviewId}`;

export const sealedContext = (interviewId, field) => `interview=${interviewId}|field=${field}`;

export const stcContext = (clinicId, field) => `clinic=${clinicId}|field=${field}`;

export const STC_INFO_PREFIX = "bobik/stc/v1|";
```

- [ ] **Krok 7: `src/crypto/keys.js`**

```js
// Import kluczy P-256 (ECDH) — lekarza, kliniki, odbiorcy grantu.
import { VaultError } from "../errors.js";

const P256 = { name: "ECDH", namedCurve: "P-256" };

// Klucz publiczny jest eksportowalny: @hpke/core serializuje pkR do kem_context.
export async function importP256Public(spki) {
  try {
    return await crypto.subtle.importKey("spki", spki, P256, true, []);
  } catch (e) {
    // DataError: bajty nie są SPKI DER albo to inna krzywa/algorytm (RSA, P-384);
    // NotSupportedError: algorytm z SPKI nieobsługiwany przez przeglądarkę.
    if (e?.name === "DataError" || e?.name === "NotSupportedError") throw new VaultError("bad_key");
    throw e;
  }
}

// Para {privateKey (extractable: false), publicKey} do HPKE-open (spike). Zeruje `pkcs8`
// zaraz po imporcie, także przy błędzie (rozstrzygnięcie 14).
export async function importP256Pair(pkcs8, publicKey) {
  try {
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, P256, false, ["deriveBits"]);
    return { privateKey, publicKey };
  } catch (e) {
    // DataError/NotSupportedError: tekst jawny grantu nie jest PKCS8 klucza P-256.
    if (e?.name === "DataError" || e?.name === "NotSupportedError") throw new VaultError("unwrap_failed");
    throw e;
  } finally {
    pkcs8.fill(0);
  }
}
```

- [ ] **Krok 8: `src/crypto/fields.js`**

```js
// F5: DEK wywiadu (clinic_wrap) i pola Sealed / SealedToClinic — format A, bez zmian.
import { bytesToUuid, concat, utf8 } from "../bytes.js";
import { VaultError } from "../errors.js";
import { dekInfo, sealedContext, STC_INFO_PREFIX, stcContext } from "./context.js";
import { ENC_LEN, hpkeOpen, isHpkeFailure } from "./hpke.js";

export const SEALED_VERSION = 0x01;
export const STC_VERSION = 0x02;
export const HEADER_LEN = 17;
const NONCE_LEN = 12;
const TAG_LEN = 16;
export const DEK_LEN = 32;
export const CLINIC_WRAP_LEN = ENC_LEN + DEK_LEN + TAG_LEN;

// Zwraca DEK jako bajty (rozstrzygnięcie 14) — wywołujący woła importDek albo wrapDekForLease, które je zerują.
export async function openClinicWrap(clinicPair, interviewId, blob) {
  if (blob.length !== CLINIC_WRAP_LEN) throw new VaultError("bad_blob");
  try {
    return await hpkeOpen(clinicPair, utf8(dekInfo(interviewId)), blob);
  } catch (e) {
    // Inny klucz kliniki albo inny wywiad w `info` — HPKE nie otwiera.
    if (isHpkeFailure(e)) throw new VaultError("decrypt_failed");
    throw e;
  }
}

export async function importDek(raw) {
  try {
    if (raw.length !== DEK_LEN) throw new VaultError("decrypt_failed");
    return await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["decrypt"]);
  } finally {
    raw.fill(0);
  }
}

export function sealedKeyId(blob) {
  if (blob.length < HEADER_LEN + NONCE_LEN + TAG_LEN || blob[0] !== SEALED_VERSION) throw new VaultError("bad_blob");
  return bytesToUuid(blob.subarray(1, HEADER_LEN));
}

export async function openSealed(dekKey, { interviewId, interviewKeyId, field, blob }) {
  if (sealedKeyId(blob) !== interviewKeyId) throw new VaultError("key_mismatch");
  const header = blob.subarray(0, HEADER_LEN);
  const aad = concat(header, utf8(`|${sealedContext(interviewId, field)}`));
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.subarray(HEADER_LEN, HEADER_LEN + NONCE_LEN), additionalData: aad, tagLength: 128 },
      dekKey,
      blob.subarray(HEADER_LEN + NONCE_LEN),
    );
  } catch (e) {
    // OperationError = zły tag: inne pole, inny wywiad albo inny DEK.
    if (e?.name === "OperationError") throw new VaultError("decrypt_failed");
    throw e;
  }
  return parseValue(new Uint8Array(plaintext));
}

export function stcKeyId(blob) {
  if (blob.length < HEADER_LEN + ENC_LEN + TAG_LEN || blob[0] !== STC_VERSION) throw new VaultError("bad_blob");
  return bytesToUuid(blob.subarray(1, HEADER_LEN));
}

export async function openStc(clinicPair, { clinicId, field, blob }) {
  stcKeyId(blob);
  const header = blob.subarray(0, HEADER_LEN);
  const info = concat(utf8(STC_INFO_PREFIX), header, utf8(`|${stcContext(clinicId, field)}`));
  let plaintext;
  try {
    plaintext = await hpkeOpen(clinicPair, info, blob.subarray(HEADER_LEN));
  } catch (e) {
    // Inna klinika albo inne pole w `info`, inny klucz kliniki.
    if (isHpkeFailure(e)) throw new VaultError("decrypt_failed");
    throw e;
  }
  return parseValue(plaintext);
}

function parseValue(plaintext) {
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch (e) {
    // TypeError: niepoprawny UTF-8 (fatal); SyntaxError: nie JSON (decyzja planu P15).
    if (e instanceof TypeError || e instanceof SyntaxError) throw new VaultError("bad_blob");
    throw e;
  }
}
```

- [ ] **Krok 9: Uruchom — mają przejść**

Run: `npx vitest run`
Expected: PASS.

- [ ] **Krok 10: Commit**

```bash
git add test/vectors test/helpers/vectors.js src/errors.js src/crypto/context.js src/crypto/keys.js src/crypto/fields.js test/unit/vectors.test.js test/unit/errors.test.js test/unit/context.test.js test/unit/keys.test.js test/unit/fields.test.js
git commit -m "feat(krypto): F5 i konteksty sejfu sprawdzane wektorami bobik2_v1.json

Kopia bobik2_v1.json z bobik-2 (suma przypięta w SHA256SUMS), konteksty F2–F5
dosłownie jak w specu, otwieranie clinic_wrap / Sealed / SealedToClinic z kodami
bad_blob / key_mismatch / decrypt_failed, VaultError i codeOf (internal bez treści).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 3: F1–F4 — klucz pakujący, wrap klucza lekarza, grant klucza kliniki

**Files:**
- Create: `src/crypto/doctor.js`, `src/crypto/clinic.js`
- Test: `test/unit/doctor.test.js`, `test/unit/clinic.test.js`

**Interfaces:**
- Consumes: `src/bytes.js`, `src/errors.js::VaultError`, `src/crypto/context.js`, `src/crypto/hpke.js`, `src/crypto/keys.js` (zadania 1–2).
- Produces:
  - `src/crypto/doctor.js`: `WRAP_VERSION = 0x01`, `deriveKek(prf: Uint8Array, doctorId, credential: string) → Promise<CryptoKey>` (zeruje `prf`), `generateDoctorKey() → Promise<{pair, spki: Uint8Array}>` (para eksportowalna), `wrapDoctorKey(privateKey, kek, aad: string) → Promise<Uint8Array>`, `unwrapDoctorKey(blob, kek, aad: string, {extractable = false}) → Promise<CryptoKey>` (`unwrap_failed`).
  - `src/crypto/clinic.js`: `GRANT_VERSION = 0x01`, `generateClinicKey() → Promise<{spki, pkcs8}>` (wywołujący zeruje `pkcs8`), `sealClinicGrant(recipientPublicKey, {clinicId, doctorId, clinicSpkiHex, pkcs8}) → Promise<Uint8Array>` (nie zeruje `pkcs8`), `openClinicGrant(doctorPair, {clinicId, doctorId, clinicSpkiHex, blob}) → Promise<Uint8Array>` (PKCS8; `unwrap_failed`).

- [ ] **Krok 1: Testy, które mają paść**

`test/unit/doctor.test.js`:

```js
import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { random, sha256Hex } from "../../src/bytes.js";
import { doctorWrapAad } from "../../src/crypto/context.js";
import { deriveKek, generateDoctorKey, unwrapDoctorKey, WRAP_VERSION, wrapDoctorKey } from "../../src/crypto/doctor.js";

const DOCTOR = 17;

async function setup() {
  const { pair, spki } = await generateDoctorKey();
  const spkiHex = await sha256Hex(spki);
  const credential = toB64url(random(16));
  const prf = random(32);
  const kek = await deriveKek(prf.slice(), DOCTOR, credential);
  const blob = await wrapDoctorKey(pair.privateKey, kek, doctorWrapAad(DOCTOR, credential, spkiHex));
  return { pair, spki, spkiHex, credential, prf, blob };
}

async function unwrap(s, { prf = s.prf, doctor = DOCTOR, credential = s.credential, spkiHex = s.spkiHex, blob = s.blob, extractable } = {}) {
  const kek = await deriveKek(prf.slice(), doctor, credential);
  return unwrapDoctorKey(blob, kek, doctorWrapAad(doctor, credential, spkiHex), { extractable });
}

describe("F1–F3: klucz pakujący i wrap klucza lekarza", () => {
  it("generateDoctorKey: para ECDH P-256 i SPKI DER (91 B)", async () => {
    const { pair, spki } = await generateDoctorKey();
    expect(pair.privateKey.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });
    expect(spki).toHaveLength(91);
  });

  it("deriveKek zeruje wynik PRF i daje nieeksportowalny AES-256-GCM do wrapKey/unwrapKey", async () => {
    const prf = random(32);
    const kek = await deriveKek(prf, DOCTOR, "AQ");
    expect(prf.every((x) => x === 0)).toBe(true);
    expect(kek.extractable).toBe(false);
    expect(kek.algorithm).toMatchObject({ name: "AES-GCM", length: 256 });
    expect([...kek.usages].sort()).toEqual(["unwrapKey", "wrapKey"]);
  });

  it("wrap = [0x01][iv 12 B][szyfrogram ‖ tag], 29–1024 B (walidator B2)", async () => {
    const s = await setup();
    expect(s.blob[0]).toBe(WRAP_VERSION);
    expect(s.blob.length).toBeGreaterThanOrEqual(29);
    expect(s.blob.length).toBeLessThanOrEqual(1024);
  });

  it("unwrap tym samym PRF i kontekstem daje nieeksportowalny klucz ECDH P-256", async () => {
    const key = await unwrap(await setup());
    expect(key.extractable).toBe(false);
    expect(key.algorithm).toMatchObject({ name: "ECDH", namedCurve: "P-256" });
  });

  it("unwrap z extractable: true (add_credential) daje klucz, który da się zapakować ponownie", async () => {
    const key = await unwrap(await setup(), { extractable: true });
    const kek2 = await deriveKek(random(32), DOCTOR, "Ag");
    expect((await wrapDoctorKey(key, kek2, "aad"))[0]).toBe(WRAP_VERSION);
  });

  it.each([
    ["inny wynik PRF (inny YubiKey)", async () => ({ prf: random(32) })],
    ["inny doctor_id", async () => ({ doctor: 18 })],
    ["inny credential", async () => ({ credential: toB64url(random(16)) })],
    ["podmieniony SPKI lekarza (B-D4)", async () => ({ spkiHex: await sha256Hex((await generateDoctorKey()).spki) })],
    ["zły bajt wersji", async (s) => { const blob = s.blob.slice(); blob[0] = 2; return { blob }; }],
    ["za krótki", async (s) => ({ blob: s.blob.slice(0, 28) })],
    ["przekłamany bajt szyfrogramu", async (s) => { const blob = s.blob.slice(); blob[20] ^= 1; return { blob }; }],
  ])("%s -> unwrap_failed", async (_name, change) => {
    const s = await setup();
    await expect(unwrap(s, await change(s))).rejects.toMatchObject({ code: "unwrap_failed" });
  });
});
```

`test/unit/clinic.test.js`:

```js
import { describe, expect, it } from "vitest";
import { sha256Hex } from "../../src/bytes.js";
import { generateClinicKey, GRANT_VERSION, openClinicGrant, sealClinicGrant } from "../../src/crypto/clinic.js";
import { generateDoctorKey } from "../../src/crypto/doctor.js";
import { importP256Pair, importP256Public } from "../../src/crypto/keys.js";

// Para lekarza jak w sejfie po unlock: prywatny nieeksportowalny + publiczny.
async function doctorPair() {
  const { pair, spki } = await generateDoctorKey();
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return importP256Pair(pkcs8, await importP256Public(spki));
}

async function setup() {
  const recipient = await doctorPair();
  const clinic = await generateClinicKey();
  const ctx = { clinicId: 3, doctorId: 17, clinicSpkiHex: await sha256Hex(clinic.spki) };
  const blob = await sealClinicGrant(recipient.publicKey, { ...ctx, pkcs8: clinic.pkcs8.slice() });
  return { recipient, clinic, ctx, blob };
}

describe("F4: grant klucza kliniki", () => {
  it("generateClinicKey: SPKI P-256 (91 B) i PKCS8", async () => {
    const { spki, pkcs8 } = await generateClinicKey();
    expect(spki).toHaveLength(91);
    expect((await importP256Public(spki)).algorithm.namedCurve).toBe("P-256");
    expect(pkcs8.length).toBeGreaterThan(100);
  });

  it("grant = [0x01][enc 65 B][szyfrogram ‖ tag]; otwiera go para odbiorcy", async () => {
    const s = await setup();
    expect(s.blob[0]).toBe(GRANT_VERSION);
    expect(s.blob).toHaveLength(1 + 65 + s.clinic.pkcs8.length + 16);
    expect(await openClinicGrant(s.recipient, { ...s.ctx, blob: s.blob })).toEqual(s.clinic.pkcs8);
  });

  it.each([
    ["inny clinic_id", async (s) => ({ ...s.ctx, clinicId: 4 })],
    ["inny doctor_id", async (s) => ({ ...s.ctx, doctorId: 18 })],
    ["podmieniony SPKI kliniki (B-D4)", async (s) => ({ ...s.ctx, clinicSpkiHex: await sha256Hex((await generateClinicKey()).spki) })],
  ])("%s -> unwrap_failed", async (_name, change) => {
    const s = await setup();
    await expect(openClinicGrant(s.recipient, { ...(await change(s)), blob: s.blob })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("para innego lekarza -> unwrap_failed", async () => {
    const s = await setup();
    await expect(openClinicGrant(await doctorPair(), { ...s.ctx, blob: s.blob })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it.each([
    ["zły bajt wersji", (blob) => { const x = blob.slice(); x[0] = 2; return x; }],
    ["za krótki (< 82 B)", (blob) => blob.slice(0, 81)],
  ])("%s -> unwrap_failed", async (_name, mutate) => {
    const s = await setup();
    await expect(openClinicGrant(s.recipient, { ...s.ctx, blob: mutate(s.blob) })).rejects.toMatchObject({ code: "unwrap_failed" });
  });
});
```

- [ ] **Krok 2: Uruchom — mają paść**

Run: `npx vitest run test/unit/doctor.test.js test/unit/clinic.test.js`
Expected: FAIL (`Cannot find module '../../src/crypto/doctor.js'`).

- [ ] **Krok 3: `src/crypto/doctor.js`**

```js
// F1–F3: wynik PRF (YubiKey) → HKDF-SHA256 → KEK (AES-256-GCM) → wrap PKCS8 klucza lekarza (ECDH P-256).
import { concat, utf8 } from "../bytes.js";
import { VaultError } from "../errors.js";
import { doctorKekInfo } from "./context.js";

export const WRAP_VERSION = 0x01;
const IV_LEN = 12;
const MIN_LEN = 1 + IV_LEN + 16;
const P256 = { name: "ECDH", namedCurve: "P-256" };

// F2. Zeruje `prf` zaraz po imporcie do HKDF (rozstrzygnięcie 14).
export async function deriveKek(prf, doctorId, credential) {
  try {
    const ikm = await crypto.subtle.importKey("raw", prf, "HKDF", false, ["deriveKey"]);
    return await crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(doctorKekInfo(doctorId, credential)) },
      ikm,
      { name: "AES-GCM", length: 256 },
      false,
      ["wrapKey", "unwrapKey"],
    );
  } finally {
    prf.fill(0);
  }
}

// Para eksportowalna wyłącznie na potrzeby wrapKey (spike: wrapKey wymaga klucza eksportowalnego).
export async function generateDoctorKey() {
  const pair = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  return { pair, spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)) };
}

// F3: [0x01][iv 12 B][AES-256-GCM(KEK, iv, PKCS8, AAD) ‖ tag 16 B].
export async function wrapDoctorKey(privateKey, kek, aad) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const ct = await crypto.subtle.wrapKey("pkcs8", privateKey, kek, { name: "AES-GCM", iv, additionalData: utf8(aad), tagLength: 128 });
  return concat(Uint8Array.of(WRAP_VERSION), iv, new Uint8Array(ct));
}

export async function unwrapDoctorKey(blob, kek, aad, { extractable = false } = {}) {
  if (blob.length < MIN_LEN || blob[0] !== WRAP_VERSION) throw new VaultError("unwrap_failed");
  try {
    return await crypto.subtle.unwrapKey(
      "pkcs8",
      blob.subarray(1 + IV_LEN),
      kek,
      { name: "AES-GCM", iv: blob.subarray(1, 1 + IV_LEN), additionalData: utf8(aad), tagLength: 128 },
      P256,
      extractable,
      ["deriveBits"],
    );
  } catch (e) {
    // OperationError: zły tag — inny YubiKey/PRF, inny doctor_id/credential, podmieniony SPKI (B-D4).
    // DataError: tag się zgodził, ale tekst jawny nie jest PKCS8 klucza P-256.
    if (e?.name === "OperationError" || e?.name === "DataError") throw new VaultError("unwrap_failed");
    throw e;
  }
}
```

- [ ] **Krok 4: `src/crypto/clinic.js`**

```js
// F4: grant klucza prywatnego kliniki = [0x01] ‖ HPKE(PKCS8 kliniki) do klucza publicznego lekarza.
import { concat, utf8 } from "../bytes.js";
import { VaultError } from "../errors.js";
import { clinicGrantInfo } from "./context.js";
import { ENC_LEN, hpkeOpen, hpkeSeal, isHpkeFailure } from "./hpke.js";

export const GRANT_VERSION = 0x01;
const MIN_LEN = 1 + ENC_LEN + 16;
const P256 = { name: "ECDH", namedCurve: "P-256" };

// Para eksportowalna tylko po to, by wyjąć SPKI i PKCS8 do pierwszego grantu (create_clinic_key).
// Wywołujący zeruje `pkcs8` zaraz po sealClinicGrant; para wychodzi z zasięgu.
export async function generateClinicKey() {
  const pair = await crypto.subtle.generateKey(P256, true, ["deriveBits"]);
  return {
    spki: new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)),
    pkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

export async function sealClinicGrant(recipientPublicKey, { clinicId, doctorId, clinicSpkiHex, pkcs8 }) {
  const sealed = await hpkeSeal(recipientPublicKey, utf8(clinicGrantInfo(clinicId, doctorId, clinicSpkiHex)), pkcs8);
  return concat(Uint8Array.of(GRANT_VERSION), sealed);
}

// Zwraca PKCS8 kliniki jako bajty (rozstrzygnięcie 14): wywołujący importuje je (importP256Pair) albo zeruje.
export async function openClinicGrant(doctorPair, { clinicId, doctorId, clinicSpkiHex, blob }) {
  if (blob.length < MIN_LEN || blob[0] !== GRANT_VERSION) throw new VaultError("unwrap_failed");
  try {
    return await hpkeOpen(doctorPair, utf8(clinicGrantInfo(clinicId, doctorId, clinicSpkiHex)), blob.subarray(1));
  } catch (e) {
    // Grant dla innego lekarza, innej kliniki albo z podmienionym SPKI kliniki — HPKE nie otwiera.
    if (isHpkeFailure(e)) throw new VaultError("unwrap_failed");
    throw e;
  }
}
```

- [ ] **Krok 5: Uruchom — mają przejść**

Run: `npx vitest run`
Expected: PASS.

- [ ] **Krok 6: Commit**

```bash
git add src/crypto/doctor.js src/crypto/clinic.js test/unit/doctor.test.js test/unit/clinic.test.js
git commit -m "feat(krypto): F1–F4 — KEK z PRF, wrap klucza lekarza i grant klucza kliniki

HKDF-SHA256 z pustą solą i info bobik/doctor-kek/v1, wrapKey pkcs8 z AAD
wiążącym SPKI lekarza (B-D4), grant HPKE z info wiążącym SPKI kliniki.
Każda niezgodność kontekstu daje unwrap_failed.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 4: F6 i wektory sejfu `sejf_v1.json` (V-1 część sejfu, V-7)

**Files:**
- Create: `src/crypto/lease.js`, `scripts/gen-vectors.mjs`, `test/vectors/sejf_v1.json` (generowany raz)
- Modify: `test/vectors/SHA256SUMS` (generowany), `package.json` (skrypt `vectors`)
- Test: `test/unit/lease.test.js`, `test/unit/sejf-vectors.test.js`

**Interfaces:**
- Consumes: zadania 1–3.
- Produces:
  - `src/crypto/lease.js`: `LEASE_MODULUS_BITS = 3072`, `RSA_WRAPPED_DEK_LEN = 384`, `importLeaseKey(spki) → Promise<CryptoKey>` (`bad_lease_key`), `wrapDekForLease(leaseKey, dek: Uint8Array) → Promise<Uint8Array>` (zeruje `dek`).
  - `test/vectors/sejf_v1.json` — kontrakt B2 (zadanie 10 planu B2) + pola testowe (P14):
    ```json
    {
      "format": "sejf_v1",
      "note": "…",
      "doctor": {"doctor_id": 17, "public_key_spki_der": "…", "fingerprint": "XXXX …"},
      "credentials": [{"credential_id": "…", "prf_salt": "…", "wrapped_private": "…", "prf_output": "…"}, {"…": "…"}],
      "clinic_grant": {"clinic_id": 3, "doctor_id": 17, "wrapped_private": "…"},
      "rsa_wrapped_dek": "…",
      "clinic_fingerprint": "XXXX …"
    }
    ```

- [ ] **Krok 1: Testy F6, które mają paść**

`test/unit/lease.test.js`:

```js
import { describe, expect, it } from "vitest";
import { importLeaseKey, RSA_WRAPPED_DEK_LEN, wrapDekForLease } from "../../src/crypto/lease.js";
import { BOBIK2, b } from "../helpers/vectors.js";

async function rsaSpki(modulusLength, publicExponent) {
  const key = await crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength, publicExponent: Uint8Array.from(publicExponent), hash: "SHA-256" },
    true,
    ["encrypt", "decrypt"],
  );
  return new Uint8Array(await crypto.subtle.exportKey("spki", key.publicKey));
}

describe("F6: DEK dla dzierżawy (V-7)", () => {
  it("klucz RSA-3072 z bobik2_v1.json: 384 B, otwiera go klucz prywatny dzierżawy, bufor DEK wyzerowany", async () => {
    const key = await importLeaseKey(b(BOBIK2.rsa_lease_key.public_key_spki_der));
    const dek = b(BOBIK2.dek);
    const wrapped = await wrapDekForLease(key, dek);
    expect(wrapped).toHaveLength(RSA_WRAPPED_DEK_LEN);
    expect(dek.every((x) => x === 0)).toBe(true);
    const priv = await crypto.subtle.importKey(
      "pkcs8",
      b(BOBIK2.rsa_lease_key.private_key_pkcs8_der),
      { name: "RSA-OAEP", hash: "SHA-256" },
      false,
      ["decrypt"],
    );
    expect(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, wrapped))).toEqual(b(BOBIK2.dek));
  });

  it("RSA-2048 -> bad_lease_key", async () => {
    await expect(importLeaseKey(await rsaSpki(2048, [1, 0, 1]))).rejects.toMatchObject({ code: "bad_lease_key" });
  });

  it("RSA-3072 z e = 3 -> bad_lease_key", async () => {
    await expect(importLeaseKey(await rsaSpki(3072, [3]))).rejects.toMatchObject({ code: "bad_lease_key" });
  }, 30_000);

  it.each([
    ["klucz EC", () => b(BOBIK2.clinic.public_key_spki_der)],
    ["śmieci", () => new Uint8Array(300).fill(1)],
  ])("%s -> bad_lease_key", async (_name, der) => {
    await expect(importLeaseKey(der())).rejects.toMatchObject({ code: "bad_lease_key" });
  });
});
```

Run: `npx vitest run test/unit/lease.test.js`
Expected: FAIL (`Cannot find module '../../src/crypto/lease.js'`).

- [ ] **Krok 2: `src/crypto/lease.js`**

```js
// F6: DEK dla dzierżawy = RSA-OAEP(SHA-256, MGF1-SHA-256, etykieta pusta) pod kluczem KMS
// RSA_DECRYPT_OAEP_3072_SHA256. WebCrypto RSA-OAEP z hash SHA-256 używa MGF1 z tym samym skrótem.
// Pochodzenia klucza sejf nie weryfikuje — ryzyko przyjęte (rozstrzygnięcie 2, B-R1).
import { VaultError } from "../errors.js";

export const LEASE_MODULUS_BITS = 3072;
export const RSA_WRAPPED_DEK_LEN = 384;
const RSA_OAEP = { name: "RSA-OAEP", hash: "SHA-256" };

export async function importLeaseKey(spki) {
  let key;
  try {
    key = await crypto.subtle.importKey("spki", spki, RSA_OAEP, false, ["encrypt"]);
  } catch (e) {
    // DataError: bajty nie są SPKI klucza RSA; NotSupportedError: algorytm nieobsługiwany.
    if (e?.name === "DataError" || e?.name === "NotSupportedError") throw new VaultError("bad_lease_key");
    throw e;
  }
  const { modulusLength, publicExponent } = key.algorithm;
  if (modulusLength !== LEASE_MODULUS_BITS || exponent(publicExponent) !== 65537) throw new VaultError("bad_lease_key");
  return key;
}

const exponent = (bytes) => bytes.reduce((n, byte) => n * 256 + byte, 0);

export async function wrapDekForLease(leaseKey, dek) {
  try {
    return new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, leaseKey, dek));
  } finally {
    dek.fill(0);
  }
}
```

Run: `npx vitest run test/unit/lease.test.js`
Expected: PASS.

- [ ] **Krok 3: Test wektorów sejfu, który ma paść**

`test/unit/sejf-vectors.test.js`:

```js
import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { sha256Hex } from "../../src/bytes.js";
import { generateClinicKey, openClinicGrant } from "../../src/crypto/clinic.js";
import { doctorWrapAad } from "../../src/crypto/context.js";
import { deriveKek, generateDoctorKey, unwrapDoctorKey } from "../../src/crypto/doctor.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { fingerprint } from "../../src/fingerprint.js";
import { BOBIK2, b, loadSejf } from "../helpers/vectors.js";

const S = loadSejf();
const clinicSpkiHex = () => sha256Hex(b(BOBIK2.clinic.public_key_spki_der));

async function doctorPair(i, { doctorId = S.doctor.doctor_id, credential = S.credentials[i].credential_id, spki = b(S.doctor.public_key_spki_der) } = {}) {
  const c = S.credentials[i];
  const kek = await deriveKek(b(c.prf_output), doctorId, credential);
  const privateKey = await unwrapDoctorKey(b(c.wrapped_private), kek, doctorWrapAad(doctorId, credential, await sha256Hex(spki)));
  return { privateKey, publicKey: await importP256Public(b(S.doctor.public_key_spki_der)) };
}

describe("sejf_v1.json (V-1, część sejfu)", () => {
  it("kształt = kontrakt B2 (zadanie 10, S-1) + pola testowe (P14)", () => {
    expect(Object.keys(S).sort()).toEqual(["clinic_fingerprint", "clinic_grant", "credentials", "doctor", "format", "note", "rsa_wrapped_dek"]);
    expect(S.format).toBe("sejf_v1");
    expect(Object.keys(S.doctor).sort()).toEqual(["doctor_id", "fingerprint", "public_key_spki_der"]);
    expect(S.credentials).toHaveLength(2);
    for (const c of S.credentials) {
      expect(Object.keys(c).sort()).toEqual(["credential_id", "prf_output", "prf_salt", "wrapped_private"]);
      expect(b(c.prf_salt)).toHaveLength(32);
      const wrap = b(c.wrapped_private);
      expect(wrap[0]).toBe(1);
      expect(wrap.length).toBeGreaterThanOrEqual(29);
      expect(wrap.length).toBeLessThanOrEqual(1024);
    }
    expect(Object.keys(S.clinic_grant).sort()).toEqual(["clinic_id", "doctor_id", "wrapped_private"]);
    expect(S.clinic_grant).toMatchObject({ clinic_id: BOBIK2.clinic_id, doctor_id: S.doctor.doctor_id });
    const grant = b(S.clinic_grant.wrapped_private);
    expect(grant[0]).toBe(1);
    expect(grant.length).toBeGreaterThanOrEqual(82);
    expect(b(S.rsa_wrapped_dek)).toHaveLength(384);
  });

  it("F7: odcisk lekarza i odcisk kliniki (= bobik-2)", async () => {
    expect(await fingerprint(b(S.doctor.public_key_spki_der))).toBe(S.doctor.fingerprint);
    expect(S.clinic_fingerprint).toBe(BOBIK2.clinic.fingerprint);
  });

  it.each([0, 1])("F1–F4: poświadczenie %i odpakowuje klucz lekarza, a ten otwiera grant kliniki z bobik2_v1.json", async (i) => {
    const pair = await doctorPair(i);
    const pkcs8 = await openClinicGrant(pair, {
      clinicId: BOBIK2.clinic_id,
      doctorId: S.doctor.doctor_id,
      clinicSpkiHex: await clinicSpkiHex(),
      blob: b(S.clinic_grant.wrapped_private),
    });
    expect(toB64url(pkcs8)).toBe(BOBIK2.clinic.private_key_pkcs8_der);
  });

  it("F6: rsa_wrapped_dek otwiera klucz dzierżawy z bobik2_v1.json", async () => {
    const priv = await crypto.subtle.importKey("pkcs8", b(BOBIK2.rsa_lease_key.private_key_pkcs8_der), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
    expect(toB64url(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b(S.rsa_wrapped_dek))))).toBe(BOBIK2.dek);
  });
});

describe("sejf_v1.json — przypadki negatywne -> unwrap_failed", () => {
  it("zły doctor_id", async () => {
    await expect(doctorPair(0, { doctorId: S.doctor.doctor_id + 1 })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("zły credential (wrap poświadczenia 0 z identyfikatorem poświadczenia 1)", async () => {
    await expect(doctorPair(0, { credential: S.credentials[1].credential_id })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("podmieniony SPKI lekarza w F3", async () => {
    await expect(doctorPair(0, { spki: (await generateDoctorKey()).spki })).rejects.toMatchObject({ code: "unwrap_failed" });
  });

  it("podmieniony SPKI kliniki w F4", async () => {
    const pair = await doctorPair(0);
    const other = await sha256Hex((await generateClinicKey()).spki);
    const args = { clinicId: BOBIK2.clinic_id, doctorId: S.doctor.doctor_id, clinicSpkiHex: other, blob: b(S.clinic_grant.wrapped_private) };
    await expect(openClinicGrant(pair, args)).rejects.toMatchObject({ code: "unwrap_failed" });
  });
});
```

Run: `npx vitest run test/unit/sejf-vectors.test.js`
Expected: FAIL (`ENOENT … test/vectors/sejf_v1.json`).

- [ ] **Krok 4: `scripts/gen-vectors.mjs`**

```js
// Generuje test/vectors/sejf_v1.json (F1–F4, F6, F7 sejfu) z podstawionym wynikiem PRF i odświeża
// test/vectors/SHA256SUMS. Uruchamiać WYŁĄCZNIE przy zmianie formatu: ECDH/HPKE/RSA-OAEP są losowe,
// więc każdy przebieg daje inne bajty, a kopia pliku żyje też w bobik-2 (spec B, „Wektory krzyżowe").
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fromB64url, toB64url } from "../src/b64.js";
import { random, sha256Hex } from "../src/bytes.js";
import { sealClinicGrant } from "../src/crypto/clinic.js";
import { doctorWrapAad } from "../src/crypto/context.js";
import { deriveKek, generateDoctorKey, wrapDoctorKey } from "../src/crypto/doctor.js";
import { importLeaseKey, wrapDekForLease } from "../src/crypto/lease.js";
import { fingerprint } from "../src/fingerprint.js";

const DIR = "test/vectors";
const DOCTOR_ID = 17;
const b2 = JSON.parse(readFileSync(`${DIR}/bobik2_v1.json`, "utf8"));

const { pair, spki } = await generateDoctorKey();
const spkiHex = await sha256Hex(spki);
const credentials = [];
for (const idLen of [16, 32]) {
  const credentialId = random(idLen);
  const prfSalt = random(32);
  const prfOutput = random(32);
  const credential = toB64url(credentialId);
  const kek = await deriveKek(prfOutput.slice(), DOCTOR_ID, credential);
  const wrapped = await wrapDoctorKey(pair.privateKey, kek, doctorWrapAad(DOCTOR_ID, credential, spkiHex));
  credentials.push({
    credential_id: credential,
    prf_salt: toB64url(prfSalt),
    wrapped_private: toB64url(wrapped),
    prf_output: toB64url(prfOutput),
  });
}

const clinicSpki = fromB64url(b2.clinic.public_key_spki_der);
const grant = await sealClinicGrant(pair.publicKey, {
  clinicId: b2.clinic_id,
  doctorId: DOCTOR_ID,
  clinicSpkiHex: await sha256Hex(clinicSpki),
  pkcs8: fromB64url(b2.clinic.private_key_pkcs8_der),
});
const leaseKey = await importLeaseKey(fromB64url(b2.rsa_lease_key.public_key_spki_der));
const rsaWrapped = await wrapDekForLease(leaseKey, fromB64url(b2.dek));

const out = {
  format: "sejf_v1",
  note:
    "Wektory formatów sejfu dla bobik-2 (spec B, „Wektory krzyżowe”). Klucze wyłącznie testowe. Bajty: base64url bez paddingu (F8). " +
    "credentials: F1/F3 — wrap klucza lekarza pod KEK z HKDF(prf_output); prf_output to podstawiony wynik PRF (tylko do testów sejfu). " +
    "clinic_grant: F4 klucza kliniki z bobik2_v1.json dla klucza lekarza z tego pliku. rsa_wrapped_dek: F6 DEK-u z bobik2_v1.json " +
    "pod rsa_lease_key z bobik2_v1.json. clinic_fingerprint: F7 SPKI kliniki z bobik2_v1.json policzone w sejfie.",
  doctor: { doctor_id: DOCTOR_ID, public_key_spki_der: toB64url(spki), fingerprint: await fingerprint(spki) },
  credentials,
  clinic_grant: { clinic_id: b2.clinic_id, doctor_id: DOCTOR_ID, wrapped_private: toB64url(grant) },
  rsa_wrapped_dek: toB64url(rsaWrapped),
  clinic_fingerprint: await fingerprint(clinicSpki),
};
writeFileSync(`${DIR}/sejf_v1.json`, `${JSON.stringify(out, null, 2)}\n`);

const sums = ["bobik2_v1.json", "sejf_v1.json"].map(
  (name) => `${createHash("sha256").update(readFileSync(`${DIR}/${name}`)).digest("hex")}  ${name}`,
);
writeFileSync(`${DIR}/SHA256SUMS`, `${sums.join("\n")}\n`);
console.log(sums.join("\n"));
```

Dopisz w `package.json` do `"scripts"`:

```json
    "vectors": "node scripts/gen-vectors.mjs",
```

- [ ] **Krok 5: Wygeneruj wektory (jeden raz) i uruchom testy**

```bash
node scripts/gen-vectors.mjs
npx vitest run
```

Expected: dwie linie sum (pierwsza bez zmian: `f9ca1b3c…  bobik2_v1.json`), wszystkie testy PASS. Od tej chwili `sejf_v1.json` jest **zamrożony**: nie uruchamiaj `gen-vectors.mjs` ponownie w tym planie (kolejne zadania czytają ten plik, a zadanie 12 przekazuje go do bobik-2).

- [ ] **Krok 6: Commit**

```bash
git add src/crypto/lease.js scripts/gen-vectors.mjs test/vectors/sejf_v1.json test/vectors/SHA256SUMS package.json test/unit/lease.test.js test/unit/sejf-vectors.test.js
git commit -m "feat(krypto): F6 i wektory sejf_v1.json dla bobik-2 (S-1)

RSA-OAEP-3072 z kontrolą modułu i e = 65537 (bad_lease_key). gen-vectors.mjs
składa sejf_v1.json w kształcie z kontraktu B2 (zadanie 10) plus prf_output do
samosprawdzenia F1–F4; plik zamrożony, sumy w test/vectors/SHA256SUMS.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 5: WebAuthn z PIN-em (`userVerification: "required"`), ścisłe base64url, atrapa authenticatora

**Files:**
- Modify: `src/webauthn.js:57` i `src/webauthn.js:89` (UV), `src/b64.js` (`B64Error`, ścisłe dekodowanie)
- Create: `test/helpers/fake-webauthn.js`
- Test: `test/unit/webauthn.test.js` (rozszerzony), `test/unit/b64.test.js` (rozszerzony), `test/unit/fake-webauthn.test.js`

**Interfaces:**
- Consumes: istniejące `registerCredential(credentials, {rpId, rpName, userId, userName, displayName, salt, excludeIds})` → `{credentialId, prfEnabled, prfFirst: Uint8Array|null, aaguid, transports}` i `evaluatePrf(credentials, {rpId, keys: [{credentialId, salt}]})` → `{index, prfFirst}` (bez zmian sygnatur).
- Produces:
  - `src/b64.js`: `class B64Error extends Error`; `fromB64url(text)` rzuca `B64Error` dla nie-tekstu, znaku spoza `[A-Za-z0-9_-]`, `=` i długości `4k+1`.
  - `test/helpers/fake-webauthn.js`: `fakeAuthenticators({prfAtCreate = true}) → {calls: {create: [], get: []}, insertNew(), insert(credentialIdB64), remove(), addFixed(rawId: Uint8Array, prfOutput: Uint8Array), credentials: {create, get}}`.

- [ ] **Krok 1: Testy, które mają paść**

W `test/unit/webauthn.test.js`, w teście `"zwraca id, prf przy rejestracji i przekazuje sól + excludeCredentials"`, zastąp linię:

```js
    expect(pk.authenticatorSelection.authenticatorAttachment).toBe("cross-platform");
```

liniami:

```js
    expect(pk.authenticatorSelection.authenticatorAttachment).toBe("cross-platform");
    // Rozstrzygnięcie 6: PIN YubiKeya obowiązkowy — hmac-secret z UV i bez UV to różne sekrety.
    expect(pk.authenticatorSelection.userVerification).toBe("required");
```

a w teście `"jedno get() z evalByCredential; wynik wskazuje klucz po rawId"` zastąp linię:

```js
    expect(pk.hints).toEqual(["security-key"]);
    expect(pk.allowCredentials).toEqual([{ type: "public-key", id: id1 }, { type: "public-key", id: id2 }]);
```

liniami:

```js
    expect(pk.hints).toEqual(["security-key"]);
    expect(pk.userVerification).toBe("required");
    expect(pk.allowCredentials).toEqual([{ type: "public-key", id: id1 }, { type: "public-key", id: id2 }]);
```

W `test/unit/b64.test.js` zastąp import i test `"odrzuca znaki spoza alfabetu"`:

```js
import { expect, it } from "vitest";
import { B64Error, fromB64url, toB64url } from "../../src/b64.js";
```

```js
it("odrzuca znaki spoza alfabetu, padding, długość 4k+1 i nie-tekst", () => {
  for (const bad of ["a+b/", "QQ==", "Q", "AAAAA", 12, null, undefined]) {
    expect(() => fromB64url(bad)).toThrow(B64Error);
  }
});
```

`test/helpers/fake-webauthn.js`:

```js
// Atrapa navigator.credentials z PRF dla testów rdzenia w Node. Modeluje fizyczne klucze:
//   insertNew()            — włożony nowy YubiKey: następne create() go rejestruje,
//   insert(id)             — włożony zarejestrowany klucz (rawId w base64url),
//   remove()               — nic nie jest włożone,
//   addFixed(rawId, prf)   — klucz z wektora sejf_v1.json: PRF zawsze zwraca `prf`.
// PRF = HMAC-SHA256(sekret klucza, sól), więc ta sama sól daje ten sam wynik (jak hmac-secret).
import { toB64url } from "../../src/b64.js";

const notAllowed = () => new DOMException("brak pasującego klucza", "NotAllowedError");
const buffer = (bytes) => bytes.slice().buffer;

async function hmac(secret, salt) {
  const key = await crypto.subtle.importKey("raw", secret, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, salt));
}

function credential(rawId, prf) {
  return {
    rawId: buffer(rawId),
    authenticatorAttachment: "cross-platform",
    response: { getTransports: () => ["usb"] },
    getClientExtensionResults: () => ({ prf }),
  };
}

export function fakeAuthenticators({ prfAtCreate = true } = {}) {
  const keys = new Map();
  let inserted = null;
  const calls = { create: [], get: [] };
  return {
    calls,
    insertNew() {
      inserted = { fresh: true };
    },
    insert(id) {
      if (!keys.has(id)) throw new Error(`atrapa: nieznany klucz ${id}`);
      inserted = { id };
    },
    remove() {
      inserted = null;
    },
    addFixed(rawId, prfOutput) {
      keys.set(toB64url(rawId), { rawId, fixed: prfOutput });
    },
    credentials: {
      async create({ publicKey }) {
        calls.create.push(publicKey);
        if (inserted?.id) {
          const excluded = publicKey.excludeCredentials.some((d) => toB64url(d.id) === inserted.id);
          throw excluded ? new DOMException("klucz już zarejestrowany", "InvalidStateError") : notAllowed();
        }
        if (!inserted?.fresh) throw notAllowed();
        const rawId = crypto.getRandomValues(new Uint8Array(16));
        const secret = crypto.getRandomValues(new Uint8Array(32));
        const id = toB64url(rawId);
        keys.set(id, { rawId, secret });
        inserted = { id };
        const salt = publicKey.extensions.prf.eval.first;
        const prf = prfAtCreate ? { enabled: true, results: { first: buffer(await hmac(secret, salt)) } } : { enabled: true };
        return credential(rawId, prf);
      },
      async get({ publicKey }) {
        calls.get.push(publicKey);
        const id = inserted?.id;
        if (!id || !publicKey.allowCredentials.some((d) => toB64url(d.id) === id)) throw notAllowed();
        const key = keys.get(id);
        const salt = publicKey.extensions.prf.evalByCredential[id].first;
        return credential(key.rawId, { results: { first: buffer(key.fixed ?? (await hmac(key.secret, salt))) } });
      },
    },
  };
}
```

`test/unit/fake-webauthn.test.js`:

```js
import { expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { evaluatePrf, registerCredential } from "../../src/webauthn.js";
import { fakeAuthenticators } from "../helpers/fake-webauthn.js";

const args = (salt, excludeIds = []) => ({ rpId: "localhost", rpName: "t", userId: new Uint8Array(4), userName: "u", displayName: "U", salt, excludeIds });

it("atrapa: PRF przy create() = PRF przy get() z tą samą solą; inna sól -> inny wynik", async () => {
  const a = fakeAuthenticators();
  a.insertNew();
  const salt = new Uint8Array(32).fill(1);
  const reg = await registerCredential(a.credentials, args(salt));
  const same = await evaluatePrf(a.credentials, { rpId: "localhost", keys: [{ credentialId: reg.credentialId, salt }] });
  expect(same.prfFirst).toEqual(reg.prfFirst);
  const other = await evaluatePrf(a.credentials, { rpId: "localhost", keys: [{ credentialId: reg.credentialId, salt: new Uint8Array(32).fill(2) }] });
  expect(other.prfFirst).not.toEqual(reg.prfFirst);
});

it("atrapa: prfAtCreate=false -> create() bez prf.results", async () => {
  const a = fakeAuthenticators({ prfAtCreate: false });
  a.insertNew();
  expect((await registerCredential(a.credentials, args(new Uint8Array(32)))).prfFirst).toBe(null);
});

it("atrapa: ten sam klucz w excludeCredentials -> already_registered; wyjęty klucz -> not_allowed", async () => {
  const a = fakeAuthenticators();
  a.insertNew();
  const reg = await registerCredential(a.credentials, args(new Uint8Array(32)));
  await expect(registerCredential(a.credentials, args(new Uint8Array(32), [reg.credentialId]))).rejects.toMatchObject({ code: "already_registered" });
  a.remove();
  const keys = [{ credentialId: reg.credentialId, salt: new Uint8Array(32) }];
  await expect(evaluatePrf(a.credentials, { rpId: "localhost", keys })).rejects.toMatchObject({ code: "not_allowed" });
});

it("atrapa: klucz z wektora daje stały PRF", async () => {
  const a = fakeAuthenticators();
  const rawId = new Uint8Array([9, 9]);
  a.addFixed(rawId, new Uint8Array(32).fill(4));
  a.insert(toB64url(rawId));
  const res = await evaluatePrf(a.credentials, { rpId: "x", keys: [{ credentialId: rawId, salt: new Uint8Array(32) }] });
  expect(res.prfFirst).toEqual(new Uint8Array(32).fill(4));
});
```

- [ ] **Krok 2: Uruchom — mają paść**

Run: `npx vitest run test/unit/webauthn.test.js test/unit/b64.test.js test/unit/fake-webauthn.test.js`
Expected: FAIL — `expected 'discouraged' to be 'required'` (2×), `B64Error` nie jest eksportowany. `fake-webauthn.test.js` PASS (atrapa działa już z obecnym kodem).

- [ ] **Krok 3: `src/webauthn.js` — UV obowiązkowe**

W `registerCredential` zastąp:

```js
        authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "discouraged", userVerification: "discouraged" },
```

linią:

```js
        // Rozstrzygnięcie 6: PIN obowiązkowy. hmac-secret z UV i bez UV to różne sekrety, więc wybór
        // wiąże wszystkie wrapy F3 na zawsze; bez PIN-u znaleziony YubiKey + kopia wrapu wystarczają.
        authenticatorSelection: { authenticatorAttachment: "cross-platform", residentKey: "discouraged", userVerification: "required" },
```

W `evaluatePrf` zastąp:

```js
        userVerification: "discouraged",
```

linią:

```js
        userVerification: "required",
```

- [ ] **Krok 4: `src/b64.js` — ścisłe dekodowanie**

Zastąp cały plik:

```js
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
```

- [ ] **Krok 5: Uruchom — mają przejść**

Run: `npx vitest run`
Expected: PASS (wszystkie pliki).

- [ ] **Krok 6: E2E demo nadal działa z PIN-em**

Sprawdź obciążenie (Global Constraints), potem:

Run: `npx playwright test test/e2e/demo.spec.js --project=chromium`
Expected: PASS (wirtualny authenticator ma `hasUserVerification: true, isUserVerified: true`). Wpisy demo zapisane w `localStorage` przeglądarki przed tą zmianą pokażą „sekret niezgodny" — to oczekiwane (inny sekret z UV), demo nie przechowuje wrapów.

- [ ] **Krok 7: Commit**

```bash
git add src/webauthn.js src/b64.js test/helpers/fake-webauthn.js test/unit/webauthn.test.js test/unit/b64.test.js test/unit/fake-webauthn.test.js
git commit -m "feat(webauthn): PIN YubiKeya obowiązkowy (userVerification required), ścisłe base64url

Rozstrzygnięcie 6: UV przy create() i get(), bo hmac-secret z UV i bez UV to
różne sekrety. fromB64url odrzuca padding, długość 4k+1 i nie-tekst (B64Error).
Atrapa navigator.credentials z PRF (HMAC) do testów rdzenia.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 6: Limit odszyfrowań, walidacja argumentów i teksty UI

**Files:**
- Create: `src/limits.js`, `src/validate.js`, `src/prompts.js`
- Test: `test/unit/limits.test.js`, `test/unit/validate.test.js`, `test/unit/prompts.test.js`

**Interfaces:**
- Consumes: `src/b64.js::{fromB64url, B64Error}` (zadanie 5), `src/errors.js::VaultError`.
- Produces:
  - `src/limits.js`: `LIMITS` (zamrożony obiekt: `INTERVIEWS_PER_UNLOCK`, `NEW_INTERVIEWS_PER_WINDOW`, `NEW_INTERVIEWS_WINDOW_MS`, `STC_PER_UNLOCK`, `STC_PER_WINDOW`, `STC_WINDOW_MS`, `IDLE_MS`, `MAX_AGE_MS`, `INTERACTION_TIMEOUT_MS`, `OPEN_MAX_ITEMS`); `createLimiter(now: () => number) → {start(), reset(), touch(), verdict({interviewIds = [], stc = 0}) → "ok"|"rate_limited"|"limit_reached", record({interviewIds = [], stc = 0}), expired() → null|"idle"|"max_age", snapshot() → {interviews, stc, idleLeftMs|null}}`.
  - `src/validate.js`: `UUID_RE`, `FIELD_RE`, `posInt(v)`, `optPosInt(v)` (`null` albo `posInt`; `undefined` → błąd), `uuid(v)`, `field(v)`, `text(v, max)`, `oneOf(v, allowed)`, `bytes(v, {min = 1, max}) → Uint8Array`, `list(v, {min = 0, max}, each)`; każdy błąd = `VaultError("bad_args")`.
  - `src/prompts.js`: `statusText(view) → string`, `formatCounters({interviews, stc, idleLeftMs}) → string`, `PROMPTS.{registerKey(n, displayName), secondTouch(n), unlock(), addExisting(), addNew(), createClinic(label), grantAccess(label, fingerprint), grantLease({kind, studyCode, sessionSeq, agentRunId})}` → `{kind, title, lines: string[], confirm, cancel}`. Etykiety przycisków (używane przez E2E): `"Zarejestruj klucz 1"`, `"Zarejestruj klucz 2"`, `"Dotknij ponownie"`, `"Odblokuj"`, `"Potwierdź istniejącym kluczem"`, `"Zarejestruj nowy klucz"`, `"Załóż klucz"`, `"Odcisk zgodny — nadaj dostęp"`, `"Zatwierdź"`; anulowanie: `"Anuluj"`, `"Odcisk niezgodny — anuluj"`, `"Odrzuć"`.

- [ ] **Krok 1: Testy, które mają paść**

`test/unit/limits.test.js`:

```js
import { describe, expect, it } from "vitest";
import { createLimiter, LIMITS } from "../../src/limits.js";

const MIN = 60_000;
const ids = (n, from = 0) => Array.from({ length: n }, (_, i) => `w${from + i}`);

function setup() {
  const clock = { t: 1_000_000 };
  const limiter = createLimiter(() => clock.t);
  limiter.start();
  return { clock, l: limiter };
}

describe("limit odszyfrowań (rozstrzygnięcie 1, V-5)", () => {
  it("wartości z tabeli specu", () => {
    expect(LIMITS).toEqual({
      INTERVIEWS_PER_UNLOCK: 50,
      NEW_INTERVIEWS_PER_WINDOW: 10,
      NEW_INTERVIEWS_WINDOW_MS: 5 * MIN,
      STC_PER_UNLOCK: 500,
      STC_PER_WINDOW: 100,
      STC_WINDOW_MS: MIN,
      IDLE_MS: 15 * MIN,
      MAX_AGE_MS: 8 * 60 * MIN,
      INTERACTION_TIMEOUT_MS: 120_000,
      OPEN_MAX_ITEMS: 1000,
    });
    expect(Object.isFrozen(LIMITS)).toBe(true);
  });

  it("10 nowych wywiadów w 5 min przechodzi, 11. -> rate_limited, po oknie znów można", () => {
    const { clock, l } = setup();
    expect(l.verdict({ interviewIds: ids(10) })).toBe("ok");
    l.record({ interviewIds: ids(10) });
    expect(l.verdict({ interviewIds: ids(1, 10) })).toBe("rate_limited");
    clock.t += 5 * MIN;
    expect(l.verdict({ interviewIds: ids(1, 10) })).toBe("ok");
  });

  it("ponowne otwarcie policzonego wywiadu nie zwiększa licznika", () => {
    const { l } = setup();
    l.record({ interviewIds: ids(10) });
    expect(l.verdict({ interviewIds: ids(10) })).toBe("ok");
    l.record({ interviewIds: [...ids(10), "w0"] });
    expect(l.snapshot().interviews).toBe(10);
  });

  it("51. wywiad w sesji -> limit_reached (pierwszeństwo przed rate_limited)", () => {
    const { clock, l } = setup();
    for (let r = 0; r < 5; r++) {
      l.record({ interviewIds: ids(10, r * 10) });
      clock.t += 5 * MIN;
    }
    expect(l.snapshot().interviews).toBe(50);
    expect(l.verdict({ interviewIds: ["nowy"] })).toBe("limit_reached");
  });

  it("STC: 100 na minutę, 500 na sesję", () => {
    const { clock, l } = setup();
    expect(l.verdict({ stc: 100 })).toBe("ok");
    l.record({ stc: 100 });
    expect(l.verdict({ stc: 1 })).toBe("rate_limited");
    for (let i = 0; i < 4; i++) {
      clock.t += MIN;
      l.record({ stc: 100 });
    }
    clock.t += MIN;
    expect(l.verdict({ stc: 1 })).toBe("limit_reached");
    expect(l.verdict({ stc: 0 })).toBe("ok");
  });

  it("jedno żądanie z 501 wartościami -> limit_reached", () => {
    expect(setup().l.verdict({ stc: 501 })).toBe("limit_reached");
  });

  it("bezczynność 15 min -> idle; aktywność odsuwa termin", () => {
    const { clock, l } = setup();
    clock.t += 14 * MIN;
    expect(l.expired()).toBe(null);
    l.touch();
    clock.t += 14 * MIN;
    expect(l.expired()).toBe(null);
    clock.t += MIN;
    expect(l.expired()).toBe("idle");
  });

  it("wiek 8 h -> max_age mimo aktywności", () => {
    const { clock, l } = setup();
    for (let i = 0; i < 47; i++) {
      clock.t += 10 * MIN;
      l.touch();
      expect(l.expired()).toBe(null);
    }
    clock.t += 10 * MIN;
    l.touch();
    expect(l.expired()).toBe("max_age");
  });

  it("snapshot: liczniki i czas do blokady; reset czyści wszystko", () => {
    const { clock, l } = setup();
    l.record({ interviewIds: ids(2), stc: 7 });
    clock.t += 61_000;
    expect(l.snapshot()).toEqual({ interviews: 2, stc: 7, idleLeftMs: 15 * MIN - 61_000 });
    l.reset();
    expect(l.expired()).toBe(null);
    expect(l.snapshot()).toEqual({ interviews: 0, stc: 0, idleLeftMs: null });
  });
});
```

`test/unit/validate.test.js`:

```js
import { describe, expect, it } from "vitest";
import { bytes, field, list, oneOf, optPosInt, posInt, text, uuid } from "../../src/validate.js";

const bad = expect.objectContaining({ code: "bad_args" });

describe("walidatory bad_args (spec B, „Walidacja argumentów")", () => {
  it("posInt: dodatnie liczby całkowite", () => {
    expect(posInt(17)).toBe(17);
    for (const v of [0, -1, 1.5, "17", null, undefined, true, Number.MAX_SAFE_INTEGER + 1]) expect(() => posInt(v)).toThrow(bad);
  });

  it("optPosInt: null albo posInt; brak klucza to błąd", () => {
    expect(optPosInt(null)).toBe(null);
    expect(optPosInt(2)).toBe(2);
    expect(() => optPosInt(undefined)).toThrow(bad);
  });

  it("uuid: małe litery z myślnikami", () => {
    expect(uuid("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b")).toBe("3f2a9c1e-5b7d-4e8f-9a0b-1c2d3e4f5a6b");
    for (const v of ["3F2A9C1E-5B7D-4E8F-9A0B-1C2D3E4F5A6B", "3f2a9c1e5b7d4e8f9a0b1c2d3e4f5a6b", "", 42]) expect(() => uuid(v)).toThrow(bad);
  });

  it("field: app_label.Model.pole", () => {
    for (const v of ["interviews.Interview.first_name", "core.WithdrawalLog.reason"]) expect(field(v)).toBe(v);
    for (const v of ["Interviews.Interview.age", "interviews.Interview", "interviews.Interview.Age", "a.b.c|x", 1]) expect(() => field(v)).toThrow(bad);
  });

  it("text: 1..max znaków", () => {
    expect(text("a", 3)).toBe("a");
    for (const v of ["", "abcd", 5, null]) expect(() => text(v, 3)).toThrow(bad);
  });

  it("oneOf", () => {
    expect(oneOf("repair", ["addendum", "repair"])).toBe("repair");
    expect(() => oneOf("x", ["a"])).toThrow(bad);
  });

  it("bytes: base64url bez paddingu, długość w granicach", () => {
    expect(bytes("AQI", { min: 2, max: 2 })).toEqual(Uint8Array.of(1, 2));
    for (const v of ["AQI=", "A+I", "AQ", null, 3]) expect(() => bytes(v, { min: 2, max: 2 })).toThrow(bad);
  });

  it("list: tablica obiektów o liczności min..max", () => {
    expect(list([{ a: 1 }], { max: 2 }, (x) => x.a)).toEqual([1]);
    for (const v of [null, {}, [1], [[]], [{}, {}, {}]]) expect(() => list(v, { max: 2 }, (x) => x)).toThrow(bad);
    expect(() => list([], { min: 1, max: 2 }, (x) => x)).toThrow(bad);
  });
});
```

`test/unit/prompts.test.js`:

```js
import { expect, it } from "vitest";
import { formatCounters, PROMPTS, statusText } from "../../src/prompts.js";

it("licznik jak w specu (rozstrzygnięcie 1)", () => {
  expect(formatCounters({ interviews: 12, stc: 40, idleLeftMs: 13 * 60_000 + 1 })).toBe("Wywiady: 12/50 · wartości kliniki: 40/500 · blokada za 14 min");
});

it("statusy po polsku", () => {
  expect(statusText({ state: "locked" })).toBe("Sejf zablokowany");
  expect(statusText({ state: "unlocked" })).toBe("Sejf odblokowany");
  expect(statusText({ state: "refusing", refusal: "revoked" })).toContain("unieważniona");
  expect(statusText({ state: "refusing", refusal: "browser_blocked" })).toContain("Safari");
  expect(statusText({ state: "refusing", refusal: "top_level" })).toBe("Sejf działa wyłącznie osadzony w panelu bobik-2.");
});

it("nadanie dostępu: etykieta i odcisk odbiorcy, przycisk potwierdzenia odcisku", () => {
  const fp = "AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH";
  const p = PROMPTS.grantAccess("dr Piotr", fp);
  expect(p.kind).toBe("grant_access");
  expect(p.lines.join("\n")).toContain("dr Piotr");
  expect(p.lines.join("\n")).toContain(fp);
  expect(p.confirm).toBe("Odcisk zgodny — nadaj dostęp");
});

it.each([
  [{ kind: "addendum", studyCode: "BOB-1", sessionSeq: null, agentRunId: null }, ["BOB-1", "dopisek", "7 dni"]],
  [{ kind: "repair", studyCode: "BOB-2", sessionSeq: 2, agentRunId: null }, ["BOB-2", "sesji 2", "1 h"]],
  [{ kind: "repair", studyCode: "BOB-3", sessionSeq: null, agentRunId: 9 }, ["BOB-3", "przebiegu agenta 9", "1 h"]],
])("dzierżawa %j: wywiad, rodzaj i czas (rozstrzygnięcie 2)", (lease, texts) => {
  const all = PROMPTS.grantLease(lease).lines.join("\n");
  for (const t of texts) expect(all).toContain(t);
});

it("każde potwierdzenie ma rodzaj, tytuł, linie i oba przyciski", () => {
  const all = [
    PROMPTS.registerKey(1, "dr A"),
    PROMPTS.registerKey(2, "dr A"),
    PROMPTS.secondTouch(1),
    PROMPTS.unlock(),
    PROMPTS.addExisting(),
    PROMPTS.addNew(),
    PROMPTS.createClinic("Klinika"),
    PROMPTS.grantAccess("dr B", "X"),
    PROMPTS.grantLease({ kind: "addendum", studyCode: "S", sessionSeq: null, agentRunId: null }),
  ];
  for (const p of all) {
    expect(typeof p.kind).toBe("string");
    expect(p.title.length).toBeGreaterThan(0);
    expect(p.lines.length).toBeGreaterThan(0);
    expect(p.confirm.length).toBeGreaterThan(0);
    expect(p.cancel.length).toBeGreaterThan(0);
  }
  expect(all.map((p) => p.confirm)).toEqual([
    "Zarejestruj klucz 1",
    "Zarejestruj klucz 2",
    "Dotknij ponownie",
    "Odblokuj",
    "Potwierdź istniejącym kluczem",
    "Zarejestruj nowy klucz",
    "Załóż klucz",
    "Odcisk zgodny — nadaj dostęp",
    "Zatwierdź",
  ]);
});
```

- [ ] **Krok 2: Uruchom — mają paść**

Run: `npx vitest run test/unit/limits.test.js test/unit/validate.test.js test/unit/prompts.test.js`
Expected: FAIL (`Cannot find module '../../src/limits.js'` itd.).

- [ ] **Krok 3: `src/limits.js`**

```js
// Limit odszyfrowań (spec B, rozstrzygnięcie 1). Liczy otwarte wywiady (rozpakowane DEK) i osobno
// wartości SealedToClinic. Wartości zmienia wyłącznie nowy release sejfu. Zegar wstrzykiwany.
export const LIMITS = Object.freeze({
  INTERVIEWS_PER_UNLOCK: 50,
  NEW_INTERVIEWS_PER_WINDOW: 10,
  NEW_INTERVIEWS_WINDOW_MS: 5 * 60_000,
  STC_PER_UNLOCK: 500,
  STC_PER_WINDOW: 100,
  STC_WINDOW_MS: 60_000,
  IDLE_MS: 15 * 60_000,
  MAX_AGE_MS: 8 * 60 * 60_000,
  INTERACTION_TIMEOUT_MS: 120_000,
  OPEN_MAX_ITEMS: 1000,
});

export function createLimiter(now) {
  let startedAt = null;
  let lastActivity = null;
  let counted = new Set();
  let stcTotal = 0;
  let interviewTimes = [];
  let stcTimes = [];

  function clear() {
    counted = new Set();
    stcTotal = 0;
    interviewTimes = [];
    stcTimes = [];
  }
  function prune(t) {
    interviewTimes = interviewTimes.filter((x) => t - x < LIMITS.NEW_INTERVIEWS_WINDOW_MS);
    stcTimes = stcTimes.filter((x) => t - x.t < LIMITS.STC_WINDOW_MS);
  }
  const fresh = (ids) => [...new Set(ids)].filter((id) => !counted.has(id));

  return {
    start() {
      startedAt = now();
      lastActivity = startedAt;
      clear();
    },
    reset() {
      startedAt = null;
      lastActivity = null;
      clear();
    },
    touch() {
      lastActivity = now();
    },
    // Czysta ocena żądania przed odszyfrowaniem; limit sesji ma pierwszeństwo przed oknem.
    verdict({ interviewIds = [], stc = 0 }) {
      prune(now());
      const n = fresh(interviewIds).length;
      if (counted.size + n > LIMITS.INTERVIEWS_PER_UNLOCK || stcTotal + stc > LIMITS.STC_PER_UNLOCK) return "limit_reached";
      const stcInWindow = stcTimes.reduce((sum, x) => sum + x.n, 0);
      if (interviewTimes.length + n > LIMITS.NEW_INTERVIEWS_PER_WINDOW || stcInWindow + stc > LIMITS.STC_PER_WINDOW) return "rate_limited";
      return "ok";
    },
    record({ interviewIds = [], stc = 0 }) {
      const t = now();
      for (const id of fresh(interviewIds)) {
        counted.add(id);
        interviewTimes.push(t);
      }
      if (stc > 0) {
        stcTotal += stc;
        stcTimes.push({ t, n: stc });
      }
    },
    expired() {
      if (startedAt === null) return null;
      const t = now();
      if (t - startedAt >= LIMITS.MAX_AGE_MS) return "max_age";
      if (t - lastActivity >= LIMITS.IDLE_MS) return "idle";
      return null;
    },
    snapshot() {
      return {
        interviews: counted.size,
        stc: stcTotal,
        idleLeftMs: startedAt === null ? null : Math.max(0, LIMITS.IDLE_MS - (now() - lastActivity)),
      };
    },
  };
}
```

- [ ] **Krok 4: `src/validate.js`**

```js
// Walidacja argumentów operacji (spec B, „Walidacja argumentów"): każdy błąd = bad_args.
import { B64Error, fromB64url } from "./b64.js";
import { VaultError } from "./errors.js";

export const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export const FIELD_RE = /^[a-z_]+\.[A-Za-z]+\.[a-z0-9_]+$/;

const bad = () => new VaultError("bad_args");

export function posInt(v) {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v <= 0) throw bad();
  return v;
}

export const optPosInt = (v) => (v === null ? null : posInt(v));

export function uuid(v) {
  if (typeof v !== "string" || !UUID_RE.test(v)) throw bad();
  return v;
}

export function field(v) {
  if (typeof v !== "string" || v.length > 200 || !FIELD_RE.test(v)) throw bad();
  return v;
}

export function text(v, max) {
  if (typeof v !== "string" || v.length < 1 || v.length > max) throw bad();
  return v;
}

export function oneOf(v, allowed) {
  if (!allowed.includes(v)) throw bad();
  return v;
}

export function bytes(v, { min = 1, max }) {
  let out;
  try {
    out = fromB64url(v);
  } catch (e) {
    // B64Error: nie tekst, znak spoza alfabetu base64url, padding albo długość 4k+1 (F8).
    if (e instanceof B64Error) throw bad();
    throw e;
  }
  if (out.length < min || out.length > max) throw bad();
  return out;
}

export function list(v, { min = 0, max }, each) {
  if (!Array.isArray(v) || v.length < min || v.length > max) throw bad();
  return v.map((item) => {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw bad();
    return each(item);
  });
}
```

- [ ] **Krok 5: `src/prompts.js`**

```js
// Teksty UI sejfu (po polsku). Etykiety od panelu są nieuwierzytelnione (B-R8), więc UI wstawia
// je wyłącznie przez textContent; kryptograficznie związane są tylko identyfikatory i klucze.
import { LIMITS } from "./limits.js";

const STATUS = { locked: "Sejf zablokowany", unlocked: "Sejf odblokowany" };
const REFUSAL = {
  revoked: "Ta wersja sejfu jest unieważniona. Panel musi przejść na nowszą wersję.",
  browser_blocked: "Ta przeglądarka nie jest obsługiwana (Safari/WebKit). Użyj Chrome, Edge albo Firefoksa z kluczem sprzętowym.",
  top_level: "Sejf działa wyłącznie osadzony w panelu bobik-2.",
};

export const statusText = (view) => (view.state === "refusing" ? REFUSAL[view.refusal] : STATUS[view.state]);

export function formatCounters({ interviews, stc, idleLeftMs }) {
  return `Wywiady: ${interviews}/${LIMITS.INTERVIEWS_PER_UNLOCK} · wartości kliniki: ${stc}/${LIMITS.STC_PER_UNLOCK} · blokada za ${Math.ceil(idleLeftMs / 60_000)} min`;
}

const TOUCH = "Kliknij przycisk, dotknij klucza i podaj jego PIN.";

export const PROMPTS = {
  registerKey: (n, displayName) => ({
    kind: "register_key",
    title: `Rejestracja klucza ${n} z 2`,
    lines: [`Lekarz: ${displayName}`, n === 1 ? "Włóż pierwszy klucz sprzętowy (YubiKey)." : "Wyjmij pierwszy klucz i włóż drugi (zapasowy).", TOUCH],
    confirm: `Zarejestruj klucz ${n}`,
    cancel: "Anuluj",
  }),
  secondTouch: (n) => ({
    kind: "second_touch",
    title: `Klucz ${n}: drugie dotknięcie`,
    lines: ["Ten klucz nie zwrócił sekretu przy rejestracji (firmware starszy niż 5.8).", TOUCH],
    confirm: "Dotknij ponownie",
    cancel: "Anuluj",
  }),
  unlock: () => ({
    kind: "unlock",
    title: "Odblokowanie sejfu",
    lines: ["Włóż jeden ze swoich kluczy sprzętowych.", TOUCH],
    confirm: "Odblokuj",
    cancel: "Anuluj",
  }),
  addExisting: () => ({
    kind: "add_existing",
    title: "Dodanie klucza — krok 1 z 2",
    lines: ["Włóż jeden z już zarejestrowanych kluczy.", TOUCH],
    confirm: "Potwierdź istniejącym kluczem",
    cancel: "Anuluj",
  }),
  addNew: () => ({
    kind: "add_new",
    title: "Dodanie klucza — krok 2 z 2",
    lines: ["Wyjmij zarejestrowany klucz i włóż nowy.", TOUCH],
    confirm: "Zarejestruj nowy klucz",
    cancel: "Anuluj",
  }),
  createClinic: (label) => ({
    kind: "create_clinic",
    title: "Nowy klucz kliniki",
    lines: [`Zakładam klucz kliniki ${label}.`, "Klucz prywatny kliniki powstaje w sejfie i nie opuszcza go w postaci jawnej."],
    confirm: "Załóż klucz",
    cancel: "Anuluj",
  }),
  grantAccess: (label, fingerprint) => ({
    kind: "grant_access",
    title: "Nadanie dostępu do kliniki",
    lines: [
      `Odbiorca: ${label}`,
      `Odcisk klucza odbiorcy: ${fingerprint}`,
      "Porównaj go z odciskiem, który odbiorca odczytał ze swojego sejfu — przez telefon albo osobiście, nie przez panel.",
    ],
    confirm: "Odcisk zgodny — nadaj dostęp",
    cancel: "Odcisk niezgodny — anuluj",
  }),
  grantLease: ({ kind, studyCode, sessionSeq, agentRunId }) => ({
    kind: "grant_lease",
    title: kind === "addendum" ? "Odblokowanie dopisku" : "Dzierżawa naprawcza",
    lines: [
      `Wywiad: ${studyCode}`,
      kind === "addendum"
        ? "Rodzaj: dopisek pacjenta"
        : sessionSeq !== null
          ? `Rodzaj: naprawa sesji ${sessionSeq}`
          : `Rodzaj: naprawa przebiegu agenta ${agentRunId}`,
      kind === "addendum" ? "Czas: 7 dni na rozpoczęcie dopisku" : "Czas: 1 h",
      "Serwer dostanie klucz tego jednego wywiadu na ten czas.",
    ],
    confirm: "Zatwierdź",
    cancel: "Odrzuć",
  }),
};
```

- [ ] **Krok 6: Uruchom — mają przejść**

Run: `npx vitest run`
Expected: PASS.

- [ ] **Krok 7: Commit**

```bash
git add src/limits.js src/validate.js src/prompts.js test/unit/limits.test.js test/unit/validate.test.js test/unit/prompts.test.js
git commit -m "feat(sejf): limit odszyfrowań z zegarem wstrzykiwanym, walidatory bad_args, teksty UI

Progi z rozstrzygnięcia 1 (50 wywiadów / 10 na 5 min / 500 i 100 na minutę
wartości kliniki / 15 min bezczynności / 8 h), limit sesji przed oknem.
Potwierdzenia po polsku: rodzaj, wywiad i czas dzierżawy, odcisk odbiorcy.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 7: Rdzeń sejfu — stany, koperta, `busy`, blokada; `hello`, `lock`, `register`, `unlock`, `add_credential`

**Files:**
- Create: `src/session.js`, `src/core.js`, `src/ops/index.js`, `src/ops/basic.js`, `src/ops/doctor.js`, `test/helpers/fake-ui.js`, `test/helpers/vault.js`
- Test: `test/unit/core.test.js`

**Interfaces:**
- Consumes: zadania 1–6; istniejące `src/protocol.js` (`parseRequest`, `okResponse`, `errorResponse`, `ProtocolError`), `src/revocation.js::isRevoked`, `src/fingerprint.js::fingerprint`, `src/config.js::VERSION`.
- Produces:
  - `src/core.js`: `createVault({version = VERSION, ready: Promise<revokedDoc|null>, browserOk: boolean, prf: Promise<boolean|null>, credentials, rpId, ui, emit: (msg) => void, now = () => Date.now(), timers = globalThis}) → {respond(data) → Promise<envelope>, tick(), lock(reason = "user"), view() → {state, refusal, fingerprint, counters}, keys() → CryptoKey[]}`. `keys()` zwraca klucze prywatne i DEK bieżącej sesji (dla testów V-6; panel nie ma do niego dostępu — inny origin).
  - Kontrakt UI (implementuje `src/ui.js` w zadaniu 9 i `test/helpers/fake-ui.js`): `ui.ask(prompt) → Promise<void>` (odrzuca `VaultError("user_rejected")` przy „Anuluj"), `ui.cancel(code)` (odrzuca oczekujące pytanie `VaultError(code)`), `ui.render(view)`.
  - Kontrakt operacji (`src/ops/*.js`): `{needs: "none"|"ready"|"unlocked", interactive: boolean, parse(req) → args, run(ctx, args, epoch) → Promise<result>}`; `ctx = {version, rpId, credentials, browserOk, prf, state, refusal, session, ask(prompt), charge(usage, {record = true}), lock(reason), unlockWith(epoch, doctor)}`.
  - `src/session.js`: `createSession() → {doctor: null | {doctorId, pair, spki, spkiHex, fingerprint}, clinics: Map<clinicKeyId, {clinicId, pair, spki, spkiHex, grant}>, deks: Map<interviewId, {interviewKeyId, key}>}`.
  - `src/ops/doctor.js`: `RP_NAME`, `register`, `unlock`, `addCredential`.
  - `test/helpers/fake-ui.js`: `fakeUi({answers = []}) → {answers, prompts, views, onAsk, hanging, ask, cancel, render}` — odpowiedzi kolejno `"ok"` (domyślnie) / `"cancel"` / `"hang"`.
  - `test/helpers/vault.js`: `makeVault({auth, ui, revoked, ready, browserOk, prf, clock}) → {vault, call(op, args), ok(op, args), auth, ui, events, timers}`, `manualTimers()`, `registerDoctor(t, {doctor_id = 17, display_name})`, `unlockDoctor(t, reg, {doctor_id = 17, index = 1})`.

- [ ] **Krok 1: Pomocnicy testów**

`test/helpers/fake-ui.js`:

```js
// Atrapa UI sejfu. Odpowiedzi kolejno z `answers`: "ok" (domyślnie), "cancel" (Anuluj),
// "hang" (lekarz nie klika — do testów blokady i limitu czasu). `onAsk(prompt, index)` pozwala
// testowi „włożyć" klucz przed wywołaniem WebAuthn, które następuje zaraz po kliknięciu.
import { VaultError } from "../../src/errors.js";

export function fakeUi({ answers = [] } = {}) {
  let next = 0;
  let hung = null;
  const ui = {
    answers,
    prompts: [],
    views: [],
    onAsk: null,
    get hanging() {
      return hung !== null;
    },
    ask(prompt) {
      ui.prompts.push(prompt);
      ui.onAsk?.(prompt, ui.prompts.length - 1);
      const answer = answers[next++] ?? "ok";
      if (answer === "cancel") return Promise.reject(new VaultError("user_rejected"));
      if (answer === "hang") return new Promise((_resolve, reject) => { hung = reject; });
      return Promise.resolve();
    },
    cancel(code) {
      if (!hung) return;
      const reject = hung;
      hung = null;
      reject(new VaultError(code));
    },
    render(view) {
      ui.views.push(view);
    },
  };
  return ui;
}
```

`test/helpers/vault.js`:

```js
// Fabryka sejfu do testów rdzenia: atrapy authenticatora i UI, zegar i timery pod kontrolą testu.
import { VERSION } from "../../src/config.js";
import { createVault } from "../../src/core.js";
import { fakeAuthenticators } from "./fake-webauthn.js";
import { fakeUi } from "./fake-ui.js";

export function manualTimers() {
  const pending = new Map();
  let n = 0;
  return {
    pending,
    setTimeout(fn) {
      pending.set(++n, fn);
      return n;
    },
    clearTimeout(id) {
      pending.delete(id);
    },
    fireAll() {
      for (const [id, fn] of [...pending]) {
        pending.delete(id);
        fn();
      }
    },
  };
}

export function makeVault({ auth = fakeAuthenticators(), ui = fakeUi(), revoked = { revoked: [] }, ready, browserOk = true, prf = true, clock } = {}) {
  const events = [];
  const timers = manualTimers();
  const vault = createVault({
    version: VERSION,
    ready: ready ?? Promise.resolve(revoked),
    browserOk,
    prf: Promise.resolve(prf),
    credentials: auth.credentials,
    rpId: "localhost",
    ui,
    emit: (msg) => events.push(msg),
    now: clock ? () => clock.t : undefined,
    timers,
  });
  let seq = 0;
  const call = (op, args = {}) => vault.respond({ v: 1, id: `t${++seq}`, op, ...args });
  async function ok(op, args) {
    const res = await call(op, args);
    if (!res.ok) throw new Error(`${op}: ${res.error}`);
    return res.result;
  }
  return { vault, call, ok, auth, ui, events, timers };
}

// Rejestracja dwóch nowych kluczy: przed każdym „Zarejestruj klucz n" wkładany jest nowy YubiKey.
export async function registerDoctor(t, { doctor_id = 17, display_name = "dr Anna Nowak" } = {}) {
  const previous = t.ui.onAsk;
  t.ui.onAsk = (prompt) => {
    if (prompt.kind === "register_key") t.auth.insertNew();
  };
  try {
    return await t.ok("register", { doctor_id, display_name });
  } finally {
    t.ui.onAsk = previous;
  }
}

export async function unlockDoctor(t, reg, { doctor_id = 17, index = 1 } = {}) {
  t.auth.insert(reg.credentials[index].credential_id);
  return t.ok("unlock", { doctor_id, public_key_der: reg.public_key_der, credentials: reg.credentials });
}
```

- [ ] **Krok 2: Test, który ma paść**

`test/unit/core.test.js`:

```js
import { describe, expect, it, vi } from "vitest";
import { fromB64url, toB64url } from "../../src/b64.js";
import { VERSION } from "../../src/config.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { fakeUi } from "../helpers/fake-ui.js";
import { fakeAuthenticators } from "../helpers/fake-webauthn.js";
import { makeVault, registerDoctor, unlockDoctor } from "../helpers/vault.js";

const REG = { doctor_id: 17, display_name: "dr Anna Nowak" };
const SALT = "A".repeat(43); // 32 B
const WRAP = "A".repeat(40); // 30 B

describe("koperta i walidacja (V-2)", () => {
  it("hello", async () => {
    const t = makeVault();
    expect(await t.call("hello")).toEqual({ v: 1, id: "t1", ok: true, result: { version: VERSION, revoked: false, browser_ok: true, prf: true, state: "locked" } });
  });

  it.each([
    [null, "bad_message"],
    [{ v: 2, id: "a", op: "hello" }, "bad_version"],
    [{ v: 1, id: "x".repeat(65), op: "hello" }, "bad_id"],
    [{ v: 1, id: "a" }, "bad_op"],
  ])("%j -> %s, id null", async (data, code) => {
    expect(await makeVault().vault.respond(data)).toEqual({ v: 1, id: null, ok: false, error: code });
  });

  it.each(["rm_rf", "toString", "__proto__", "constructor"])("operacja %s -> unknown_op", async (op) => {
    expect(await makeVault().call(op)).toMatchObject({ ok: false, error: "unknown_op" });
  });

  it.each([
    ["register", { display_name: "dr A" }],
    ["register", { doctor_id: 0, display_name: "dr A" }],
    ["register", { doctor_id: "17", display_name: "dr A" }],
    ["register", { doctor_id: 17, display_name: "" }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [] }],
    ["unlock", { doctor_id: 17, public_key_der: "A+AA", credentials: [{ credential_id: "AQ", prf_salt: SALT, wrapped_private: WRAP }] }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [{ credential_id: "AQ", prf_salt: "AQ", wrapped_private: WRAP }] }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [{ credential_id: "AQ", prf_salt: SALT, wrapped_private: "AQ" }] }],
    ["unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [{ credential_id: "", prf_salt: SALT, wrapped_private: WRAP }] }],
  ])("%s %j -> bad_args", async (op, args) => {
    expect(await makeVault().call(op, args)).toMatchObject({ ok: false, error: "bad_args" });
  });
});

describe("register (V-8, rozstrzygnięcie 16, P1)", () => {
  it("dwa klucze, UV required, excludeCredentials; wynik do POST doctor-key/; sejf zostaje zablokowany", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const [c1, c2] = t.auth.calls.create;
    expect(c1.authenticatorSelection.userVerification).toBe("required");
    expect(c1.excludeCredentials).toEqual([]);
    expect(c2.excludeCredentials.map((d) => new Uint8Array(d.id))).toEqual([fromB64url(reg.credentials[0].credential_id)]);
    expect(t.auth.calls.get).toHaveLength(0);
    expect(reg.credentials).toHaveLength(2);
    expect(reg.credentials[0].prf_salt).not.toBe(reg.credentials[1].prf_salt);
    for (const c of reg.credentials) {
      expect(fromB64url(c.prf_salt)).toHaveLength(32);
      expect(fromB64url(c.wrapped_private)[0]).toBe(1);
    }
    expect(reg.fingerprint).toMatch(/^([A-Z2-7]{4} ){7}[A-Z2-7]{4}$/);
    expect((await importP256Public(fromB64url(reg.public_key_der))).algorithm.namedCurve).toBe("P-256");
    expect(t.ui.prompts.map((p) => p.kind)).toEqual(["register_key", "register_key"]);
    expect((await t.call("hello")).result.state).toBe("locked");
  });

  it("klucz bez PRF przy create() -> drugie dotknięcie (get z UV) dla każdego klucza", async () => {
    const t = makeVault({ auth: fakeAuthenticators({ prfAtCreate: false }) });
    const reg = await registerDoctor(t);
    expect(t.ui.prompts.map((p) => p.kind)).toEqual(["register_key", "second_touch", "register_key", "second_touch"]);
    expect(t.auth.calls.get).toHaveLength(2);
    expect(t.auth.calls.get[0].userVerification).toBe("required");
    expect(await unlockDoctor(t, reg)).toEqual({ fingerprint: reg.fingerprint });
  });

  it("ten sam YubiKey jako drugi -> already_registered, a sejf przyjmuje kolejną operację", async () => {
    const t = makeVault();
    t.ui.onAsk = (_prompt, index) => {
      if (index === 0) t.auth.insertNew(); // przy drugim pytaniu zostaje włożony pierwszy klucz
    };
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "already_registered" });
    t.ui.onAsk = null;
    expect((await registerDoctor(t)).credentials).toHaveLength(2);
  });

  it("lekarz anuluje -> user_rejected, WebAuthn nie wołane", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["cancel"] }) });
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "user_rejected" });
    expect(t.auth.calls.create).toHaveLength(0);
  });

  it("brak klucza w porcie -> not_allowed", async () => {
    expect(await makeVault().call("register", REG)).toMatchObject({ ok: false, error: "not_allowed" });
  });
});

describe("unlock", () => {
  it("jedno get() z evalByCredential; drugi klucz; odcisk = odcisk z rejestracji; klucz nieeksportowalny", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    expect(await unlockDoctor(t, reg, { index: 0 })).toEqual({ fingerprint: reg.fingerprint });
    const get = t.auth.calls.get.at(-1);
    expect(get.userVerification).toBe("required");
    expect(Object.keys(get.extensions.prf.evalByCredential).sort()).toEqual(reg.credentials.map((c) => c.credential_id).sort());
    expect((await t.call("hello")).result.state).toBe("unlocked");
    expect(t.vault.keys()).toHaveLength(1);
    expect(t.vault.keys().every((k) => k.extractable === false)).toBe(true);
    expect(t.vault.view()).toMatchObject({ state: "unlocked", fingerprint: reg.fingerprint, counters: { interviews: 0, stc: 0 } });
    expect(t.events).toEqual([]);
  });

  it("poświadczenia prosto z GET state/ (nadmiarowe id, label, created_at) są przyjmowane (P5)", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const fromState = reg.credentials.map((c, i) => ({ id: i + 1, label: "", created_at: "2026-10-25T10:00:00+00:00", ...c }));
    t.auth.insert(reg.credentials[1].credential_id);
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: fromState })).toMatchObject({ ok: true });
  });

  it("podmieniony klucz publiczny lekarza -> unwrap_failed, sejf zablokowany (B-D4)", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    const other = await registerDoctor(t, { doctor_id: 18 });
    t.auth.insert(reg.credentials[1].credential_id);
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: other.public_key_der, credentials: reg.credentials })).toMatchObject({ ok: false, error: "unwrap_failed" });
    expect((await t.call("hello")).result.state).toBe("locked");
  });

  it("inny doctor_id -> unwrap_failed", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await expect(unlockDoctor(t, reg, { doctor_id: 18 })).rejects.toThrow("unlock: unwrap_failed");
  });

  it("klucz publiczny spoza P-256 -> bad_key", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    t.auth.insert(reg.credentials[1].credential_id);
    const junk = toB64url(new Uint8Array(91).fill(7));
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: junk, credentials: reg.credentials })).toMatchObject({ ok: false, error: "bad_key" });
  });

  it("włożony klucz spoza listy -> not_allowed", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    t.auth.insertNew();
    expect(await t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials })).toMatchObject({ ok: false, error: "not_allowed" });
  });
});

describe("add_credential (F3, B-D5)", () => {
  it("istniejący klucz -> nowy klucz; nowym wrapem da się odblokować", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await unlockDoctor(t, reg);
    t.ui.onAsk = (prompt) => {
      if (prompt.kind === "add_existing") t.auth.insert(reg.credentials[0].credential_id);
      if (prompt.kind === "add_new") t.auth.insertNew();
    };
    const { credential } = await t.ok("add_credential", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials });
    t.ui.onAsk = null;
    expect(t.ui.prompts.slice(-2).map((p) => p.kind)).toEqual(["add_existing", "add_new"]);
    expect(t.auth.calls.create.at(-1).excludeCredentials).toHaveLength(2);
    expect(fromB64url(credential.wrapped_private)[0]).toBe(1);
    await t.ok("lock");
    t.auth.insert(credential.credential_id);
    const all = [...reg.credentials, credential];
    expect(await t.ok("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: all })).toEqual({ fingerprint: reg.fingerprint });
  });

  it("lekarz inny niż odblokowany -> bad_args", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await unlockDoctor(t, reg);
    expect(await t.call("add_credential", { doctor_id: 18, public_key_der: reg.public_key_der, credentials: reg.credentials })).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("w stanie locked -> locked (przed walidacją argumentów)", async () => {
    expect(await makeVault().call("add_credential", {})).toMatchObject({ ok: false, error: "locked" });
  });
});

describe("stany (V-4)", () => {
  it.each([[{ revoked: [VERSION] }], [null], [{}], [{ revoked: VERSION }]])("lista unieważnień %j -> refusing/revoked", async (doc) => {
    const t = makeVault({ revoked: doc });
    expect((await t.call("hello")).result).toMatchObject({ revoked: true, state: "refusing" });
    for (const op of ["register", "unlock", "lock", "add_credential"]) {
      expect(await t.call(op, {})).toMatchObject({ ok: false, error: "revoked" });
    }
    expect(t.ui.views.at(-1)).toMatchObject({ state: "refusing", refusal: "revoked" });
  });

  it("przeglądarka zablokowana -> refusing/browser_blocked (D13)", async () => {
    const t = makeVault({ browserOk: false });
    expect((await t.call("hello")).result).toMatchObject({ browser_ok: false, revoked: false, state: "refusing" });
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "browser_blocked" });
    expect(await t.call("unlock", {})).toMatchObject({ ok: false, error: "browser_blocked" });
  });

  it("żądanie przed pobraniem revoked.json czeka na listę zamiast dostać locked", async () => {
    let resolve;
    const ready = new Promise((r) => { resolve = r; });
    const t = makeVault({ ready });
    let done = false;
    const pending = t.call("hello").then((res) => { done = true; return res; });
    await new Promise((r) => setTimeout(r, 20));
    expect(done).toBe(false);
    resolve({ revoked: [] });
    expect((await pending).result.state).toBe("locked");
  });

  it("lock w stanie locked: {} bez zdarzenia", async () => {
    const t = makeVault();
    expect(await t.ok("lock")).toEqual({});
    expect(t.events).toEqual([]);
  });

  it("lock po odblokowaniu: klucze usunięte, zdarzenie locked/user; vault.lock() (przycisk) tak samo", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    await unlockDoctor(t, reg);
    expect(await t.ok("lock")).toEqual({});
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "user" }]);
    expect(t.vault.keys()).toEqual([]);
    expect((await t.call("hello")).result.state).toBe("locked");
    await unlockDoctor(t, reg);
    t.vault.lock();
    expect(t.events.at(-1)).toEqual({ v: 1, event: "locked", reason: "user" });
  });
});

describe("busy, blokada w trakcie operacji, limit czasu (P3, P4, Review Focus 1)", () => {
  it("druga operacja interaktywna -> busy; hello działa; lock przerywa pierwszą kodem locked", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["hang"] }) });
    const first = t.call("register", REG);
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    expect(await t.call("register", REG)).toMatchObject({ ok: false, error: "busy" });
    expect(await t.call("hello")).toMatchObject({ ok: true });
    await t.ok("lock");
    expect(await first).toMatchObject({ ok: false, error: "locked" });
    expect((await registerDoctor(t)).credentials).toHaveLength(2);
  });

  it("unlock z wiszącym potwierdzeniem + blokada -> locked i brak kluczy", async () => {
    const t = makeVault();
    const reg = await registerDoctor(t);
    t.ui.answers.push("hang");
    t.auth.insert(reg.credentials[0].credential_id);
    const pending = t.call("unlock", { doctor_id: 17, public_key_der: reg.public_key_der, credentials: reg.credentials });
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    t.vault.lock();
    expect(await pending).toMatchObject({ ok: false, error: "locked" });
    expect((await t.call("hello")).result.state).toBe("locked");
    expect(t.vault.keys()).toEqual([]);
  });

  it("potwierdzenie bez odpowiedzi przez 120 s -> user_rejected", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["hang"] }) });
    const pending = t.call("register", REG);
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    expect(t.timers.pending.size).toBe(1);
    t.timers.fireAll();
    expect(await pending).toMatchObject({ ok: false, error: "user_rejected" });
  });

  it("nieprzewidziany wyjątek -> internal, w konsoli tylko typ", async () => {
    const spy = vi.spyOn(console, "error").mockImplementation(() => {});
    const auth = fakeAuthenticators();
    auth.credentials.create = async () => ({ broken: true });
    expect(await makeVault({ auth }).call("register", REG)).toMatchObject({ ok: false, error: "internal" });
    expect(spy).toHaveBeenCalledWith("sejf: nieprzewidziany błąd", "TypeError");
    spy.mockRestore();
  });
});
```

- [ ] **Krok 3: Uruchom — ma paść**

Run: `npx vitest run test/unit/core.test.js`
Expected: FAIL (`Cannot find module '../../src/core.js'`).

- [ ] **Krok 4: `src/session.js`**

```js
// Klucze jednej sesji odblokowania — wyłącznie w pamięci (rozstrzygnięcie 13). Blokada podmienia
// cały obiekt, więc operacja zaczęta przed blokadą pisze do porzuconej sesji (P3).
export function createSession() {
  return { doctor: null, clinics: new Map(), deks: new Map() };
}
```

- [ ] **Krok 5: `src/core.js`**

```js
// Rdzeń sejfu: koperta, stany (refusing / locked / unlocked), busy, limit, blokada.
// Wszystko, co zależy od przeglądarki (DOM, postMessage, navigator.credentials, zegar), jest
// wstrzykiwane przez vault.js — rdzeń testuje się w Node (Vitest).
import { VERSION } from "./config.js";
import { codeOf, VaultError } from "./errors.js";
import { createLimiter, LIMITS } from "./limits.js";
import { OPS } from "./ops/index.js";
import { errorResponse, okResponse, parseRequest, ProtocolError } from "./protocol.js";
import { isRevoked } from "./revocation.js";
import { createSession } from "./session.js";

export function createVault({ version = VERSION, ready, browserOk, prf, credentials, rpId, ui, emit, now = () => Date.now(), timers = globalThis }) {
  let state = "locked";
  let refusal = null;
  let busy = false;
  let epoch = 0;
  let session = createSession();
  const limiter = createLimiter(now);

  const view = () => ({
    state,
    refusal,
    fingerprint: session.doctor?.fingerprint ?? null,
    counters: state === "unlocked" ? limiter.snapshot() : null,
  });
  const render = () => ui.render(view());

  // Żądania czekają na listę unieważnień (V-4): odpowiedź `locked` przed jej pobraniem
  // pozwoliłaby unieważnionej wersji przyjąć `register` / `unlock`.
  const init = ready.then((doc) => {
    if (isRevoked(version, doc)) {
      state = "refusing";
      refusal = "revoked";
    } else if (!browserOk) {
      state = "refusing";
      refusal = "browser_blocked";
    }
    render();
  });

  function lock(reason) {
    if (state === "refusing") return;
    const wasUnlocked = state === "unlocked";
    epoch += 1;
    session = createSession();
    limiter.reset();
    state = "locked";
    ui.cancel("locked");
    render();
    if (wasUnlocked) emit({ v: 1, event: "locked", reason });
  }

  // Potwierdzenie w UI sejfu; bez odpowiedzi przez 120 s → user_rejected (P4).
  function ask(prompt) {
    const timer = timers.setTimeout(() => ui.cancel("user_rejected"), LIMITS.INTERACTION_TIMEOUT_MS);
    return ui.ask(prompt).finally(() => timers.clearTimeout(timer));
  }

  // Limit (rozstrzygnięcie 1) sprawdzany przed pierwszym odszyfrowaniem; limit_reached blokuje sejf.
  function charge(usage, { record = true } = {}) {
    const verdict = limiter.verdict(usage);
    if (verdict === "limit_reached") {
      lock("limit");
      throw new VaultError("limit_reached");
    }
    if (verdict === "rate_limited") throw new VaultError("rate_limited");
    if (record) limiter.record(usage);
  }

  const ctx = {
    version,
    rpId,
    credentials,
    browserOk,
    prf,
    get state() {
      return state;
    },
    get refusal() {
      return refusal;
    },
    get session() {
      return session;
    },
    ask,
    charge,
    lock,
    unlockWith(startEpoch, doctor) {
      if (epoch !== startEpoch) throw new VaultError("locked");
      epoch += 1; // operacje sprzed ponownego odblokowania nie oddadzą wyników starymi kluczami
      session = createSession();
      session.doctor = doctor;
      state = "unlocked";
      limiter.start();
      render();
    },
  };

  async function dispatch(req) {
    const op = Object.hasOwn(OPS, req.op) ? OPS[req.op] : null;
    if (!op) throw new ProtocolError("unknown_op");
    if (op.needs !== "none" && state === "refusing") throw new VaultError(refusal);
    if (op.needs === "unlocked" && state !== "unlocked") throw new VaultError("locked");
    const args = op.parse(req);
    if (op.interactive && busy) throw new VaultError("busy");
    if (op.interactive) busy = true;
    const start = epoch;
    try {
      if (op.needs === "unlocked") limiter.touch();
      const result = await op.run(ctx, args, start);
      // Blokada w trakcie operacji: wynik policzony kluczami poprzedniej sesji nie wraca (P3).
      if (op.needs === "unlocked" && epoch !== start) throw new VaultError("locked");
      return result;
    } finally {
      if (op.interactive) busy = false;
    }
  }

  async function respond(data) {
    let id = null;
    try {
      const req = parseRequest(data);
      id = req.id;
      await init;
      return okResponse(id, await dispatch(req));
    } catch (e) {
      return errorResponse(id, codeOf(e));
    } finally {
      render();
    }
  }

  function tick() {
    if (state !== "unlocked") return;
    const reason = limiter.expired();
    if (reason) lock(reason);
    else render();
  }

  function keys() {
    const out = [];
    if (session.doctor) out.push(session.doctor.pair.privateKey);
    for (const clinic of session.clinics.values()) out.push(clinic.pair.privateKey);
    for (const dek of session.deks.values()) out.push(dek.key);
    return out;
  }

  return { respond, tick, lock: (reason = "user") => lock(reason), view, keys };
}
```

- [ ] **Krok 6: `src/ops/basic.js` i `src/ops/index.js`**

`src/ops/basic.js`:

```js
// hello i lock — jedyne operacje bez kluczy.

export const hello = {
  needs: "none",
  interactive: false,
  parse: () => ({}),
  async run(ctx) {
    return { version: ctx.version, revoked: ctx.refusal === "revoked", browser_ok: ctx.browserOk, prf: await ctx.prf, state: ctx.state };
  },
};

export const lock = {
  needs: "ready",
  interactive: false,
  parse: () => ({}),
  async run(ctx) {
    ctx.lock("user");
    return {};
  },
};
```

`src/ops/index.js`:

```js
// Tabela operacji protokołu (spec B, „Operacje"). Klucze = nazwy `op`.
import { hello, lock } from "./basic.js";
import { addCredential, register, unlock } from "./doctor.js";

export const OPS = Object.freeze({
  hello,
  register,
  unlock,
  add_credential: addCredential,
  lock,
});
```

- [ ] **Krok 7: `src/ops/doctor.js`**

```js
// register, unlock, add_credential (spec B, „Operacje"; F1–F3; B-D5; rozstrzygnięcia 6 i 16).
// Każde wywołanie WebAuthn następuje zaraz po kliknięciu przycisku w sejfie (aktywacja użytkownika
// w iframe'ie), bez innych await pomiędzy.
import { toB64url } from "../b64.js";
import { random, sha256Hex, utf8 } from "../bytes.js";
import { doctorWrapAad } from "../crypto/context.js";
import { deriveKek, generateDoctorKey, unwrapDoctorKey, wrapDoctorKey } from "../crypto/doctor.js";
import { importP256Public } from "../crypto/keys.js";
import { VaultError } from "../errors.js";
import { fingerprint } from "../fingerprint.js";
import { PROMPTS } from "../prompts.js";
import { bytes, list, posInt, text } from "../validate.js";
import { evaluatePrf, registerCredential } from "../webauthn.js";

export const RP_NAME = "Sejf kluczy bobik";
const PRF_SALT_LEN = 32;
const userHandle = (doctorId) => utf8(`bobik-doctor-${doctorId}`);

function parseCredentials(value) {
  return list(value, { min: 1, max: 10 }, (c) => ({
    credentialId: bytes(c.credential_id, { min: 1, max: 1023 }),
    prfSalt: bytes(c.prf_salt, { min: PRF_SALT_LEN, max: PRF_SALT_LEN }),
    wrapped: bytes(c.wrapped_private, { min: 29, max: 1024 }),
  }));
}

const parseDoctorKey = (req) => ({
  doctorId: posInt(req.doctor_id),
  spki: bytes(req.public_key_der, { max: 1024 }),
  credentials: parseCredentials(req.credentials),
});

// Jeden nowy YubiKey: create() z PRF; bez prf.results (firmware < 5.8) drugie dotknięcie get().
async function enroll(ctx, { doctorId, displayName, excludeIds, prompt, touchPrompt }) {
  await ctx.ask(prompt);
  const salt = random(PRF_SALT_LEN);
  const reg = await registerCredential(ctx.credentials, {
    rpId: ctx.rpId,
    rpName: RP_NAME,
    userId: userHandle(doctorId),
    userName: `lekarz-${doctorId}`,
    displayName,
    salt,
    excludeIds,
  });
  let prf = reg.prfFirst;
  if (!prf) {
    await ctx.ask(touchPrompt);
    prf = (await evaluatePrf(ctx.credentials, { rpId: ctx.rpId, keys: [{ credentialId: reg.credentialId, salt }] })).prfFirst;
  }
  return { credentialId: reg.credentialId, salt, prf };
}

async function wrapFor(privateKey, doctorId, spkiHex, enrolled) {
  const credential = toB64url(enrolled.credentialId);
  const kek = await deriveKek(enrolled.prf, doctorId, credential); // zeruje enrolled.prf
  const blob = await wrapDoctorKey(privateKey, kek, doctorWrapAad(doctorId, credential, spkiHex));
  return { credential_id: credential, prf_salt: toB64url(enrolled.salt), wrapped_private: toB64url(blob) };
}

// Jedno get() z evalByCredential: odpowiada włożony klucz, wrap wybierany po rawId (spike 1b).
async function unwrapWith(ctx, { doctorId, spkiHex, credentials }, { extractable }) {
  const { index, prfFirst } = await evaluatePrf(ctx.credentials, {
    rpId: ctx.rpId,
    keys: credentials.map((c) => ({ credentialId: c.credentialId, salt: c.prfSalt })),
  });
  const chosen = credentials[index];
  const credential = toB64url(chosen.credentialId);
  const kek = await deriveKek(prfFirst, doctorId, credential);
  return unwrapDoctorKey(chosen.wrapped, kek, doctorWrapAad(doctorId, credential, spkiHex), { extractable });
}

export const register = {
  needs: "ready",
  interactive: true,
  parse: (req) => ({ doctorId: posInt(req.doctor_id), displayName: text(req.display_name, 200) }),
  async run(ctx, { doctorId, displayName }) {
    const enrolled = [];
    try {
      for (const n of [1, 2]) {
        enrolled.push(
          await enroll(ctx, {
            doctorId,
            displayName,
            excludeIds: enrolled.map((e) => e.credentialId),
            prompt: PROMPTS.registerKey(n, displayName),
            touchPrompt: PROMPTS.secondTouch(n),
          }),
        );
      }
      // Para eksportowalna wyłącznie na dwa wrapKey; sejf zostaje zablokowany (decyzja planu P1).
      const { pair, spki } = await generateDoctorKey();
      const spkiHex = await sha256Hex(spki);
      const credentials = [];
      for (const e of enrolled) credentials.push(await wrapFor(pair.privateKey, doctorId, spkiHex, e));
      return { public_key_der: toB64url(spki), fingerprint: await fingerprint(spki), credentials };
    } finally {
      for (const e of enrolled) e.prf.fill(0);
    }
  },
};

export const unlock = {
  needs: "ready",
  interactive: true,
  parse: parseDoctorKey,
  async run(ctx, { doctorId, spki, credentials }, epoch) {
    const publicKey = await importP256Public(spki);
    const spkiHex = await sha256Hex(spki);
    await ctx.ask(PROMPTS.unlock());
    const privateKey = await unwrapWith(ctx, { doctorId, spkiHex, credentials }, { extractable: false });
    const fp = await fingerprint(spki);
    ctx.unlockWith(epoch, { doctorId, pair: { privateKey, publicKey }, spki, spkiHex, fingerprint: fp });
    return { fingerprint: fp };
  },
};

export const addCredential = {
  needs: "unlocked",
  interactive: true,
  parse: parseDoctorKey,
  async run(ctx, { doctorId, spki, credentials }) {
    const doctor = ctx.session.doctor;
    const spkiHex = await sha256Hex(spki);
    if (doctorId !== doctor.doctorId || spkiHex !== doctor.spkiHex) throw new VaultError("bad_args");
    await ctx.ask(PROMPTS.addExisting());
    // F3: chwilowa kopia eksportowalna wyłącznie do wrapKey dla nowego klucza, potem porzucona.
    const exportable = await unwrapWith(ctx, { doctorId, spkiHex, credentials }, { extractable: true });
    const added = await enroll(ctx, {
      doctorId,
      displayName: `Lekarz ${doctorId}`,
      excludeIds: credentials.map((c) => c.credentialId),
      prompt: PROMPTS.addNew(),
      touchPrompt: PROMPTS.secondTouch(3),
    });
    try {
      return { credential: await wrapFor(exportable, doctorId, spkiHex, added) };
    } finally {
      added.prf.fill(0);
    }
  },
};
```

- [ ] **Krok 8: Uruchom — mają przejść**

Run: `npx vitest run`
Expected: PASS (w tym `core.test.js`).

- [ ] **Krok 9: Commit**

```bash
git add src/session.js src/core.js src/ops test/helpers/fake-ui.js test/helpers/vault.js test/unit/core.test.js
git commit -m "feat(sejf): rdzeń — stany refusing/locked/unlocked, busy, blokada; register, unlock, add_credential

Rejestracja dwóch YubiKeyów w jednej ceremonii (drugie dotknięcie przy braku
PRF w create()), unlock jednym get() z evalByCredential, add_credential przez
chwilową kopię eksportowalną. Blokada przerywa oczekujące potwierdzenie i
unieważnia wyniki operacji sprzed blokady; żądania czekają na revoked.json.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 8: Operacje na kluczach kliniki, `open` i `grant_lease` (V-1 pełny łańcuch, V-5, V-6)

**Files:**
- Create: `src/ops/clinic.js`, `src/ops/open.js`, `src/ops/lease.js`
- Modify: `src/ops/index.js` (pełna tabela operacji), `test/helpers/vault.js` (`unlockFromVector`, `loadBobik2Clinic`)
- Test: `test/unit/ops-clinic.test.js`, `test/unit/ops-open.test.js`, `test/unit/ops-lease.test.js`

**Interfaces:**
- Consumes: kontrakt operacji i `ctx` z zadania 7; `openClinicGrant`, `sealClinicGrant`, `generateClinicKey` (zadanie 3); `openClinicWrap`, `importDek`, `openSealed`, `openStc`, `stcKeyId` (zadanie 2); `importLeaseKey`, `wrapDekForLease` (zadanie 4); walidatory (zadanie 6); wektory `sejf_v1.json` (zadanie 4).
- Produces:
  - `src/ops/clinic.js`: `loadClinicKey`, `createClinicKey`, `grantClinicAccess`; wpis sesji `session.clinics.set(clinicKeyId, {clinicId, pair, spki, spkiHex, grant})` — `grant_clinic_access` bierze `clinic_id` z wpisu zapisanego przez `load_clinic_key` (protokół nie przekazuje go drugi raz).
  - `src/ops/open.js`: `open` — wynik `{values: [{ok: true, value} | {ok: false, error}]}` w kolejności `items`.
  - `src/ops/lease.js`: `grantLease` — wynik `{rsa_wrapped_dek}`.
  - `test/helpers/vault.js`: `unlockFromVector(t) → S` (odblokowanie lekarzem z `sejf_v1.json`, klucze z podstawionym PRF), `loadBobik2Clinic(t, S) → {clinic_key_id, fingerprint}`.

- [ ] **Krok 1: Pomocnicy w `test/helpers/vault.js`**

Dopisz importy na górze pliku:

```js
import { fromB64url } from "../../src/b64.js";
import { BOBIK2, loadSejf } from "./vectors.js";
```

i na końcu pliku:

```js
// Odblokowanie lekarzem z sejf_v1.json: „klucze" atrapy zwracają prf_output z wektora.
export async function unlockFromVector(t) {
  const S = loadSejf();
  for (const c of S.credentials) t.auth.addFixed(fromB64url(c.credential_id), fromB64url(c.prf_output));
  t.auth.insert(S.credentials[0].credential_id);
  await t.ok("unlock", { doctor_id: S.doctor.doctor_id, public_key_der: S.doctor.public_key_spki_der, credentials: S.credentials });
  return S;
}

// Klucz kliniki z bobik2_v1.json, otwierany grantem F4 z sejf_v1.json.
export function loadBobik2Clinic(t, S) {
  return t.ok("load_clinic_key", {
    clinic_id: BOBIK2.clinic_id,
    clinic_key_id: BOBIK2.clinic_key_id,
    clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
    wrapped_private: S.clinic_grant.wrapped_private,
  });
}
```

- [ ] **Krok 2: Testy, które mają paść**

`test/unit/ops-clinic.test.js`:

```js
import { describe, expect, it } from "vitest";
import { fromB64url, toB64url } from "../../src/b64.js";
import { generateClinicKey } from "../../src/crypto/clinic.js";
import { fakeUi } from "../helpers/fake-ui.js";
import { BOBIK2 } from "../helpers/vectors.js";
import { loadBobik2Clinic, makeVault, registerDoctor, unlockDoctor, unlockFromVector } from "../helpers/vault.js";

const NEW_KEY_ID = "0b6f7a52-1c1e-4a7e-9d43-2a1f5e8c9d10";
const JUNK_KEY = toB64url(new Uint8Array(91).fill(7));

describe("load_clinic_key (F4, V-1, V-6)", () => {
  it("grant z sejf_v1.json otwiera klucz kliniki z bobik2_v1.json; odcisk = odcisk z bobik-2", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    expect(await loadBobik2Clinic(t, S)).toEqual({ clinic_key_id: BOBIK2.clinic_key_id, fingerprint: BOBIK2.clinic.fingerprint });
    expect(t.vault.keys()).toHaveLength(2);
    expect(t.vault.keys().every((k) => k.extractable === false)).toBe(true);
  });

  it.each([
    ["inny clinic_id (info grantu)", async () => ({ clinic_id: BOBIK2.clinic_id + 1 })],
    ["inny klucz publiczny kliniki (B-D4)", async () => ({ clinic_public_key_der: toB64url((await generateClinicKey()).spki) })],
  ])("%s -> unwrap_failed", async (_name, change) => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    const args = {
      clinic_id: BOBIK2.clinic_id,
      clinic_key_id: BOBIK2.clinic_key_id,
      clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
      wrapped_private: S.clinic_grant.wrapped_private,
      ...(await change()),
    };
    expect(await t.call("load_clinic_key", args)).toMatchObject({ ok: false, error: "unwrap_failed" });
  });

  it("klucz publiczny kliniki nie-P-256 -> bad_key; grant < 82 B -> bad_args", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    const base = { clinic_id: BOBIK2.clinic_id, clinic_key_id: BOBIK2.clinic_key_id, clinic_public_key_der: BOBIK2.clinic.public_key_spki_der, wrapped_private: S.clinic_grant.wrapped_private };
    expect(await t.call("load_clinic_key", { ...base, clinic_public_key_der: JUNK_KEY })).toMatchObject({ ok: false, error: "bad_key" });
    expect(await t.call("load_clinic_key", { ...base, wrapped_private: "AQID" })).toMatchObject({ ok: false, error: "bad_args" });
  });
});

describe("create_clinic_key (F4)", () => {
  it("potwierdzenie z etykietą, grant dla siebie; do pamięci dopiero przez load_clinic_key", async () => {
    const t = makeVault();
    await unlockFromVector(t);
    const created = await t.ok("create_clinic_key", { clinic_id: 5, clinic_label: "Klinika Testowa" });
    const prompt = t.ui.prompts.at(-1);
    expect(prompt.kind).toBe("create_clinic");
    expect(prompt.lines.join("\n")).toContain("Zakładam klucz kliniki Klinika Testowa.");
    expect(fromB64url(created.wrapped_private)[0]).toBe(1);
    expect(t.vault.keys()).toHaveLength(1);
    const loaded = await t.ok("load_clinic_key", {
      clinic_id: 5,
      clinic_key_id: NEW_KEY_ID,
      clinic_public_key_der: created.clinic_public_key_der,
      wrapped_private: created.wrapped_private,
    });
    expect(loaded).toEqual({ clinic_key_id: NEW_KEY_ID, fingerprint: created.fingerprint });
  });

  it("odrzucenie -> user_rejected", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["ok", "cancel"] }) });
    await unlockFromVector(t);
    expect(await t.call("create_clinic_key", { clinic_id: 5, clinic_label: "Klinika" })).toMatchObject({ ok: false, error: "user_rejected" });
  });
});

describe("grant_clinic_access (F4, D5, B-D4)", () => {
  it("odcisk odbiorcy w potwierdzeniu; odbiorca otwiera grant swoim sejfem", async () => {
    const a = makeVault();
    const S = await unlockFromVector(a);
    await loadBobik2Clinic(a, S);
    const b = makeVault();
    const regB = await registerDoctor(b, { doctor_id: 18, display_name: "dr Piotr Zieliński" });
    const granted = await a.ok("grant_clinic_access", {
      clinic_key_id: BOBIK2.clinic_key_id,
      recipient_doctor_id: 18,
      recipient_label: "dr Piotr Zieliński",
      recipient_public_key_der: regB.public_key_der,
    });
    const prompt = a.ui.prompts.at(-1);
    expect(prompt.kind).toBe("grant_access");
    expect(prompt.lines.join("\n")).toContain(regB.fingerprint);
    expect(prompt.lines.join("\n")).toContain("dr Piotr Zieliński");
    expect(granted.recipient_fingerprint).toBe(regB.fingerprint);
    await unlockDoctor(b, regB, { doctor_id: 18 });
    const loaded = await b.ok("load_clinic_key", {
      clinic_id: BOBIK2.clinic_id,
      clinic_key_id: BOBIK2.clinic_key_id,
      clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
      wrapped_private: granted.wrapped_private,
    });
    expect(loaded).toEqual({ clinic_key_id: BOBIK2.clinic_key_id, fingerprint: BOBIK2.clinic.fingerprint });
  });

  it("niezaładowany klucz kliniki -> clinic_key_not_loaded; zły klucz odbiorcy -> bad_key", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: "dr P", recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "clinic_key_not_loaded" });
    await loadBobik2Clinic(t, S);
    expect(await t.call("grant_clinic_access", { ...args, recipient_public_key_der: JUNK_KEY })).toMatchObject({ ok: false, error: "bad_key" });
  });

  it("odcisk niezgodny (Anuluj) -> user_rejected", async () => {
    const t = makeVault({ ui: fakeUi({ answers: ["ok", "cancel"] }) });
    const S = await unlockFromVector(t);
    await loadBobik2Clinic(t, S);
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: "dr P", recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "user_rejected" });
  });

  it("ponowne unlock czyści klucze kliniki", async () => {
    const t = makeVault();
    const S = await unlockFromVector(t);
    await loadBobik2Clinic(t, S);
    t.auth.insert(S.credentials[1].credential_id);
    await t.ok("unlock", { doctor_id: S.doctor.doctor_id, public_key_der: S.doctor.public_key_spki_der, credentials: S.credentials });
    const args = { clinic_key_id: BOBIK2.clinic_key_id, recipient_doctor_id: 18, recipient_label: "dr P", recipient_public_key_der: S.doctor.public_key_spki_der };
    expect(await t.call("grant_clinic_access", args)).toMatchObject({ ok: false, error: "clinic_key_not_loaded" });
  });
});

describe("stan locked (V-4)", () => {
  it.each(["load_clinic_key", "create_clinic_key", "grant_clinic_access", "open", "grant_lease", "add_credential"])("%s -> locked", async (op) => {
    expect(await makeVault().call(op, {})).toMatchObject({ ok: false, error: "locked" });
  });
});
```

`test/unit/ops-open.test.js`:

```js
import { describe, expect, it } from "vitest";
import { toB64url } from "../../src/b64.js";
import { random, utf8 } from "../../src/bytes.js";
import { dekInfo } from "../../src/crypto/context.js";
import { hpkeSeal } from "../../src/crypto/hpke.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { BOBIK2, b, bobik2ExpectedValues, bobik2OpenRequest } from "../helpers/vectors.js";
import { loadBobik2Clinic, makeVault, unlockFromVector } from "../helpers/vault.js";

const MIN = 60_000;
const stcItem = { kind: "stc", clinic_id: BOBIK2.clinic_id, field: BOBIK2.stc[0].field, blob: BOBIK2.stc[0].blob };

async function ready(opts) {
  const t = makeVault(opts);
  const S = await unlockFromVector(t);
  await loadBobik2Clinic(t, S);
  return t;
}

// Wywiady pod kluczem kliniki z bobik2_v1.json z losowym DEK — do testów limitu.
async function fakeInterviews(n) {
  const pub = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  const out = [];
  for (let i = 0; i < n; i++) {
    const id = crypto.randomUUID();
    const wrap = await hpkeSeal(pub, utf8(dekInfo(id)), random(32));
    out.push({ interview_id: id, interview_key_id: crypto.randomUUID(), clinic_key_id: BOBIK2.clinic_key_id, clinic_wrap: toB64url(wrap) });
  }
  return out;
}

describe("open z wektorami bobik2_v1.json (V-1, V-6)", () => {
  it("Sealed, SealedToClinic i przypadki negatywne, w kolejności items", async () => {
    const t = await ready();
    expect(await t.ok("open", bobik2OpenRequest())).toEqual({ values: bobik2ExpectedValues() });
    expect(t.vault.keys()).toHaveLength(3); // lekarz, klinika, DEK
    expect(t.vault.keys().every((k) => k.extractable === false)).toBe(true);
    expect(t.vault.view().counters.interviews).toBe(1);
  });

  it("puste żądanie -> pusta lista", async () => {
    const t = await ready();
    expect(await t.ok("open", { interviews: [], items: [] })).toEqual({ values: [] });
  });
});

describe("open: błędy per element i bad_args (Review Focus 3)", () => {
  it("element sealed bez wpisu w interviews -> unknown_interview", async () => {
    const t = await ready();
    const { items } = bobik2OpenRequest();
    expect(await t.ok("open", { interviews: [], items: [items[0]] })).toEqual({ values: [{ ok: false, error: "unknown_interview" }] });
  });

  it("wywiad z niezaładowanym kluczem kliniki -> clinic_key_not_loaded dla jego pól", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    const interviews = [{ ...req.interviews[0], clinic_key_id: "00000000-0000-4000-8000-000000000001" }];
    expect((await t.ok("open", { interviews, items: [req.items[0]] })).values).toEqual([{ ok: false, error: "clinic_key_not_loaded" }]);
  });

  it("clinic_wrap innego wywiadu -> decrypt_failed dla jego pól", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    const [other] = await fakeInterviews(1);
    const interviews = [{ ...req.interviews[0], clinic_wrap: other.clinic_wrap }];
    expect((await t.ok("open", { interviews, items: [req.items[0]] })).values).toEqual([{ ok: false, error: "decrypt_failed" }]);
  });

  it("STC: klucz z nagłówka należy do innej kliniki -> key_mismatch", async () => {
    const t = await ready();
    expect((await t.ok("open", { interviews: [], items: [{ ...stcItem, clinic_id: BOBIK2.clinic_id + 1 }] })).values).toEqual([{ ok: false, error: "key_mismatch" }]);
  });

  it("STC: nagłówek wskazuje niezaładowany klucz kliniki -> clinic_key_not_loaded", async () => {
    const t = await ready();
    const blob = b(stcItem.blob);
    blob.fill(0, 1, 17);
    expect((await t.ok("open", { interviews: [], items: [{ ...stcItem, blob: toB64url(blob) }] })).values).toEqual([{ ok: false, error: "clinic_key_not_loaded" }]);
  });

  it("ucięty Sealed -> bad_blob", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    const item = { ...req.items[0], blob: toB64url(b(req.items[0].blob).slice(0, 20)) };
    expect((await t.ok("open", { interviews: req.interviews, items: [item] })).values).toEqual([{ ok: false, error: "bad_blob" }]);
  });

  it.each([
    ["powtórzony interview_id", (r) => { r.interviews.push({ ...r.interviews[0] }); }],
    ["blob null (pole puste w ciphertexts — panel je pomija, P5)", (r) => { r.items[0].blob = null; }],
    ["element sealed bez interview_id", (r) => { delete r.items[0].interview_id; }],
    ["zły field", (r) => { r.items[0].field = "x"; }],
    ["zły kind", (r) => { r.items[0].kind = "dek"; }],
    ["> 1000 elementów", (r) => { r.items = Array(1001).fill(stcItem); }],
    ["interviews nie jest tablicą", (r) => { r.interviews = {}; }],
    ["clinic_id tekstem", (r) => { r.items[3].clinic_id = "3"; }],
  ])("%s -> bad_args", async (_name, mutate) => {
    const t = await ready();
    const req = bobik2OpenRequest();
    mutate(req);
    expect(await t.call("open", req)).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("ponowne otwarcie z innym interview_key_id: DEK odpakowany ponownie, stare bloby -> key_mismatch, licznik bez zmian", async () => {
    const t = await ready();
    const req = bobik2OpenRequest();
    expect((await t.ok("open", { interviews: req.interviews, items: [req.items[0]] })).values[0]).toMatchObject({ ok: true });
    const rekeyed = { ...req.interviews[0], interview_key_id: "99999999-8888-4777-8666-555555555555" };
    expect((await t.ok("open", { interviews: [rekeyed], items: [req.items[0]] })).values).toEqual([{ ok: false, error: "key_mismatch" }]);
    expect(t.vault.view().counters.interviews).toBe(1);
  });
});

describe("limit w open (V-5)", () => {
  it("10 nowych wywiadów przechodzi, 11. -> rate_limited bez blokady; po 5 min znów można", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    const iv = await fakeInterviews(11);
    expect(await t.ok("open", { interviews: iv.slice(0, 10), items: [] })).toEqual({ values: [] });
    expect(await t.call("open", { interviews: [iv[10]], items: [] })).toMatchObject({ ok: false, error: "rate_limited" });
    expect(t.events).toEqual([]);
    expect(await t.ok("open", { interviews: iv.slice(0, 10), items: [] })).toEqual({ values: [] }); // DEK w pamięci: bez kosztu
    clock.t += 5 * MIN;
    expect(await t.call("open", { interviews: [iv[10]], items: [] })).toMatchObject({ ok: true });
    expect(t.ui.views.at(-1).counters).toMatchObject({ interviews: 11 });
  });

  it("51. wywiad -> limit_reached, auto-blokada, zdarzenie locked/limit, klucze usunięte", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    const iv = await fakeInterviews(51);
    for (let r = 0; r < 5; r++) {
      await t.ok("open", { interviews: iv.slice(r * 10, r * 10 + 10), items: [] });
      clock.t += 5 * MIN;
    }
    expect(t.vault.view().counters.interviews).toBe(50);
    expect(await t.call("open", { interviews: [iv[50]], items: [] })).toMatchObject({ ok: false, error: "limit_reached" });
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "limit" }]);
    expect(t.vault.keys()).toEqual([]);
    expect(await t.call("open", { interviews: [], items: [] })).toMatchObject({ ok: false, error: "locked" });
  }, 30_000);

  it("STC: 100 na minutę -> rate_limited; 501. w sesji -> limit_reached", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    const hundred = Array(100).fill(stcItem);
    expect((await t.ok("open", { interviews: [], items: hundred })).values).toHaveLength(100);
    expect(await t.call("open", { interviews: [], items: [stcItem] })).toMatchObject({ ok: false, error: "rate_limited" });
    for (let i = 0; i < 4; i++) {
      clock.t += MIN;
      await t.ok("open", { interviews: [], items: hundred });
    }
    clock.t += MIN;
    expect(await t.call("open", { interviews: [], items: [stcItem] })).toMatchObject({ ok: false, error: "limit_reached" });
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "limit" }]);
  }, 60_000);

  it("bezczynność 15 min -> tick blokuje (idle)", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    clock.t += 15 * MIN;
    t.vault.tick();
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "idle" }]);
    expect(t.vault.keys()).toEqual([]);
  });

  it("wiek 8 h -> max_age mimo aktywności", async () => {
    const clock = { t: 1_000_000 };
    const t = await ready({ clock });
    for (let i = 1; i < 48; i++) {
      clock.t += 10 * MIN;
      await t.ok("open", { interviews: [], items: [] });
      t.vault.tick();
    }
    expect(t.events).toEqual([]);
    clock.t += 10 * MIN;
    t.vault.tick();
    expect(t.events).toEqual([{ v: 1, event: "locked", reason: "max_age" }]);
  });
});
```

`test/unit/ops-lease.test.js`:

```js
import { describe, expect, it, vi } from "vitest";
import { toB64url } from "../../src/b64.js";
import { fakeUi } from "../helpers/fake-ui.js";
import { BOBIK2, b, bobik2LeaseArgs } from "../helpers/vectors.js";
import { loadBobik2Clinic, makeVault, unlockFromVector } from "../helpers/vault.js";

async function ready(opts) {
  const t = makeVault(opts);
  const S = await unlockFromVector(t);
  await loadBobik2Clinic(t, S);
  return t;
}

async function openWithLeaseKey(wrapped) {
  const priv = await crypto.subtle.importKey("pkcs8", b(BOBIK2.rsa_lease_key.private_key_pkcs8_der), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  return toB64url(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b(wrapped))));
}

async function rsa2048Spki() {
  const k = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: "SHA-256" }, true, ["encrypt"]);
  return toB64url(new Uint8Array(await crypto.subtle.exportKey("spki", k.publicKey)));
}

describe("grant_lease (F6, rozstrzygnięcie 2)", () => {
  it("dopisek: lekarz widzi wywiad, rodzaj i czas; DEK pod kluczem dzierżawy; liczy się raz jako otwarcie wywiadu", async () => {
    const t = await ready();
    const res = await t.ok("grant_lease", bobik2LeaseArgs());
    const lines = t.ui.prompts.at(-1).lines.join("\n");
    expect(t.ui.prompts.at(-1).kind).toBe("grant_lease");
    expect(lines).toContain("BOB-0001");
    expect(lines).toContain("7 dni");
    expect(b(res.rsa_wrapped_dek)).toHaveLength(384);
    expect(await openWithLeaseKey(res.rsa_wrapped_dek)).toBe(BOBIK2.dek);
    expect(t.vault.view().counters.interviews).toBe(1);
    await t.ok("grant_lease", bobik2LeaseArgs());
    expect(t.vault.view().counters.interviews).toBe(1);
  });

  it.each([
    [{ kind: "repair", session_seq: 2 }, "sesji 2"],
    [{ kind: "repair", agent_run_id: 9 }, "przebiegu agenta 9"],
  ])("naprawa %j", async (over, text) => {
    const t = await ready();
    await t.ok("grant_lease", bobik2LeaseArgs(over));
    const lines = t.ui.prompts.at(-1).lines.join("\n");
    expect(lines).toContain(text);
    expect(lines).toContain("1 h");
  });

  it.each([
    ["dopisek z session_seq", { session_seq: 1 }],
    ["naprawa bez celu", { kind: "repair" }],
    ["naprawa z sesją i przebiegiem", { kind: "repair", session_seq: 1, agent_run_id: 2 }],
    ["brak klucza session_seq", { session_seq: undefined }],
    ["nieznany rodzaj", { kind: "interview" }],
    ["pusty study_code", { study_code: "" }],
    ["zły interview_id", { interview_id: "42" }],
  ])("%s -> bad_args", async (_name, over) => {
    const t = await ready();
    expect(await t.call("grant_lease", bobik2LeaseArgs(over))).toMatchObject({ ok: false, error: "bad_args" });
  });

  it("klucz dzierżawy RSA-2048 albo EC -> bad_lease_key", async () => {
    const t = await ready();
    expect(await t.call("grant_lease", bobik2LeaseArgs({ lease_public_key_der: await rsa2048Spki() }))).toMatchObject({ ok: false, error: "bad_lease_key" });
    expect(await t.call("grant_lease", bobik2LeaseArgs({ lease_public_key_der: BOBIK2.clinic.public_key_spki_der }))).toMatchObject({ ok: false, error: "bad_lease_key" });
  });

  it("niezaładowany klucz kliniki -> clinic_key_not_loaded", async () => {
    const t = await ready();
    expect(await t.call("grant_lease", bobik2LeaseArgs({ clinic_key_id: "00000000-0000-4000-8000-000000000001" }))).toMatchObject({ ok: false, error: "clinic_key_not_loaded" });
  });

  it("odrzucenie -> user_rejected, licznik bez zmian", async () => {
    const t = await ready({ ui: fakeUi({ answers: ["ok", "cancel"] }) });
    expect(await t.call("grant_lease", bobik2LeaseArgs())).toMatchObject({ ok: false, error: "user_rejected" });
    expect(t.vault.view().counters.interviews).toBe(0);
  });

  it("blokada przy wiszącym potwierdzeniu -> locked, bez rsa_wrapped_dek (Review Focus 1)", async () => {
    const t = await ready({ ui: fakeUi({ answers: ["ok", "hang"] }) });
    const pending = t.call("grant_lease", bobik2LeaseArgs());
    await vi.waitFor(() => expect(t.ui.hanging).toBe(true));
    t.vault.lock();
    expect(await pending).toEqual({ v: 1, id: expect.any(String), ok: false, error: "locked" });
  });
});
```

- [ ] **Krok 3: Uruchom — mają paść**

Run: `npx vitest run test/unit/ops-clinic.test.js test/unit/ops-open.test.js test/unit/ops-lease.test.js`
Expected: FAIL — `unknown_op` dla `load_clinic_key`, `open`, `grant_lease` (operacji nie ma w `OPS`), stąd `Error: load_clinic_key: unknown_op` w pomocnikach.

- [ ] **Krok 4: `src/ops/clinic.js`**

```js
// load_clinic_key, create_clinic_key, grant_clinic_access (F4; rozstrzygnięcia 3 i 14; B-D4).
import { toB64url } from "../b64.js";
import { sha256Hex } from "../bytes.js";
import { generateClinicKey, openClinicGrant, sealClinicGrant } from "../crypto/clinic.js";
import { importP256Pair, importP256Public } from "../crypto/keys.js";
import { VaultError } from "../errors.js";
import { fingerprint } from "../fingerprint.js";
import { PROMPTS } from "../prompts.js";
import { bytes, posInt, text, uuid } from "../validate.js";

export const loadClinicKey = {
  needs: "unlocked",
  interactive: false,
  parse: (req) => ({
    clinicId: posInt(req.clinic_id),
    clinicKeyId: uuid(req.clinic_key_id),
    spki: bytes(req.clinic_public_key_der, { max: 1024 }),
    grant: bytes(req.wrapped_private, { min: 82, max: 1024 }),
  }),
  async run(ctx, { clinicId, clinicKeyId, spki, grant }) {
    const session = ctx.session;
    const doctor = session.doctor;
    const publicKey = await importP256Public(spki);
    const spkiHex = await sha256Hex(spki);
    const pkcs8 = await openClinicGrant(doctor.pair, { clinicId, doctorId: doctor.doctorId, clinicSpkiHex: spkiHex, blob: grant });
    const pair = await importP256Pair(pkcs8, publicKey); // zeruje pkcs8
    // Bajty grantu zostają: grant_clinic_access otwiera go ponownie zamiast eksportować klucz (spike).
    session.clinics.set(clinicKeyId, { clinicId, pair, spki, spkiHex, grant });
    return { clinic_key_id: clinicKeyId, fingerprint: await fingerprint(spki) };
  },
};

export const createClinicKey = {
  needs: "unlocked",
  interactive: true,
  parse: (req) => ({ clinicId: posInt(req.clinic_id), label: text(req.clinic_label, 200) }),
  async run(ctx, { clinicId, label }) {
    const doctor = ctx.session.doctor;
    await ctx.ask(PROMPTS.createClinic(label));
    const { spki, pkcs8 } = await generateClinicKey();
    try {
      const blob = await sealClinicGrant(doctor.pair.publicKey, {
        clinicId,
        doctorId: doctor.doctorId,
        clinicSpkiHex: await sha256Hex(spki),
        pkcs8,
      });
      // Klucz kliniki trafia do pamięci dopiero przez load_clinic_key po zapisie na serwerze (F4).
      return { clinic_public_key_der: toB64url(spki), wrapped_private: toB64url(blob), fingerprint: await fingerprint(spki) };
    } finally {
      pkcs8.fill(0);
    }
  },
};

export const grantClinicAccess = {
  needs: "unlocked",
  interactive: true,
  parse: (req) => ({
    clinicKeyId: uuid(req.clinic_key_id),
    recipientId: posInt(req.recipient_doctor_id),
    label: text(req.recipient_label, 200),
    recipientSpki: bytes(req.recipient_public_key_der, { max: 1024 }),
  }),
  async run(ctx, { clinicKeyId, recipientId, label, recipientSpki }) {
    const session = ctx.session;
    const doctor = session.doctor;
    const clinic = session.clinics.get(clinicKeyId);
    if (!clinic) throw new VaultError("clinic_key_not_loaded");
    const recipientKey = await importP256Public(recipientSpki);
    // Odcisk liczony w sejfie z klucza, do którego sejf zaraz zapakuje grant (B-D4).
    const recipientFingerprint = await fingerprint(recipientSpki);
    await ctx.ask(PROMPTS.grantAccess(label, recipientFingerprint));
    const pkcs8 = await openClinicGrant(doctor.pair, {
      clinicId: clinic.clinicId,
      doctorId: doctor.doctorId,
      clinicSpkiHex: clinic.spkiHex,
      blob: clinic.grant,
    });
    try {
      const blob = await sealClinicGrant(recipientKey, { clinicId: clinic.clinicId, doctorId: recipientId, clinicSpkiHex: clinic.spkiHex, pkcs8 });
      return { wrapped_private: toB64url(blob), recipient_fingerprint: recipientFingerprint };
    } finally {
      pkcs8.fill(0);
    }
  },
};
```

- [ ] **Krok 5: `src/ops/open.js`**

```js
// open (F5): DEK wywiadów z clinic_wrap, pola Sealed i SealedToClinic. Limit sprawdzany dla całego
// żądania przed pierwszym odszyfrowaniem; błędy pojedynczych elementów idą per element.
import { importDek, openClinicWrap, openSealed, openStc, stcKeyId } from "../crypto/fields.js";
import { VaultError } from "../errors.js";
import { LIMITS } from "../limits.js";
import { bytes, field, list, oneOf, posInt, uuid } from "../validate.js";

const MAX = LIMITS.OPEN_MAX_ITEMS;

function parseItem(item) {
  const kind = oneOf(item.kind, ["sealed", "stc"]);
  const common = { kind, field: field(item.field), blob: bytes(item.blob, { max: 1 << 20 }) };
  return kind === "sealed" ? { ...common, interviewId: uuid(item.interview_id) } : { ...common, clinicId: posInt(item.clinic_id) };
}

export const open = {
  needs: "unlocked",
  interactive: false,
  parse(req) {
    const interviews = list(req.interviews, { max: MAX }, (e) => ({
      interviewId: uuid(e.interview_id),
      interviewKeyId: uuid(e.interview_key_id),
      clinicKeyId: uuid(e.clinic_key_id),
      clinicWrap: bytes(e.clinic_wrap, { max: 1024 }),
    }));
    if (new Set(interviews.map((e) => e.interviewId)).size !== interviews.length) throw new VaultError("bad_args");
    return { interviews, items: list(req.items, { max: MAX }, parseItem) };
  },
  async run(ctx, { interviews, items }) {
    const session = ctx.session;
    ctx.charge({ interviewIds: interviews.map((e) => e.interviewId), stc: items.filter((i) => i.kind === "stc").length });
    const deks = new Map();
    for (const entry of interviews) deks.set(entry.interviewId, await dekFor(session, entry));
    const values = [];
    for (const item of items) values.push(await openItem(session, deks, item));
    return { values };
  },
};

// DEK z pamięci, gdy ten sam InterviewKey; inaczej z clinic_wrap (i zapis w sesji).
async function dekFor(session, entry) {
  const cached = session.deks.get(entry.interviewId);
  if (cached && cached.interviewKeyId === entry.interviewKeyId) return { entry, key: cached.key };
  const clinic = session.clinics.get(entry.clinicKeyId);
  if (!clinic) return { error: "clinic_key_not_loaded" };
  try {
    const key = await importDek(await openClinicWrap(clinic.pair, entry.interviewId, entry.clinicWrap));
    session.deks.set(entry.interviewId, { interviewKeyId: entry.interviewKeyId, key });
    return { entry, key };
  } catch (e) {
    // VaultError z openClinicWrap/importDek (bad_blob, decrypt_failed) dotyczy pól tego wywiadu.
    if (e instanceof VaultError) return { error: e.code };
    throw e;
  }
}

async function openItem(session, deks, item) {
  try {
    if (item.kind === "sealed") {
      const dek = deks.get(item.interviewId);
      if (!dek) return { ok: false, error: "unknown_interview" };
      if (dek.error) return { ok: false, error: dek.error };
      const value = await openSealed(dek.key, {
        interviewId: item.interviewId,
        interviewKeyId: dek.entry.interviewKeyId,
        field: item.field,
        blob: item.blob,
      });
      return { ok: true, value };
    }
    const clinic = session.clinics.get(stcKeyId(item.blob));
    if (!clinic) return { ok: false, error: "clinic_key_not_loaded" };
    if (clinic.clinicId !== item.clinicId) return { ok: false, error: "key_mismatch" };
    return { ok: true, value: await openStc(clinic.pair, item) };
  } catch (e) {
    // VaultError = kod elementu (bad_blob, key_mismatch, decrypt_failed); reszta to błąd sejfu.
    if (e instanceof VaultError) return { ok: false, error: e.code };
    throw e;
  }
}
```

- [ ] **Krok 6: `src/ops/lease.js`**

```js
// grant_lease (F6): lekarz zatwierdza w sejfie rodzaj, wywiad i czas; DEK pod kluczem dzierżawy.
// Pochodzenie klucza dzierżawy nie jest weryfikowane (rozstrzygnięcie 2); study_code to etykieta (B-R8).
import { toB64url } from "../b64.js";
import { openClinicWrap } from "../crypto/fields.js";
import { importLeaseKey, wrapDekForLease } from "../crypto/lease.js";
import { VaultError } from "../errors.js";
import { PROMPTS } from "../prompts.js";
import { bytes, oneOf, optPosInt, text, uuid } from "../validate.js";

export const grantLease = {
  needs: "unlocked",
  interactive: true,
  parse(req) {
    const kind = oneOf(req.kind, ["addendum", "repair"]);
    const sessionSeq = optPosInt(req.session_seq);
    const agentRunId = optPosInt(req.agent_run_id);
    const target = kind === "addendum" ? sessionSeq === null && agentRunId === null : (sessionSeq === null) !== (agentRunId === null);
    if (!target) throw new VaultError("bad_args");
    return {
      interviewId: uuid(req.interview_id),
      interviewKeyId: uuid(req.interview_key_id),
      clinicKeyId: uuid(req.clinic_key_id),
      clinicWrap: bytes(req.clinic_wrap, { max: 1024 }),
      studyCode: text(req.study_code, 64),
      kind,
      sessionSeq,
      agentRunId,
      leaseSpki: bytes(req.lease_public_key_der, { max: 2048 }),
    };
  },
  async run(ctx, a) {
    const clinic = ctx.session.clinics.get(a.clinicKeyId);
    if (!clinic) throw new VaultError("clinic_key_not_loaded");
    const leaseKey = await importLeaseKey(a.leaseSpki);
    const usage = { interviewIds: [a.interviewId], stc: 0 };
    ctx.charge(usage, { record: false }); // limit przed pytaniem, koszt dopiero po zatwierdzeniu (P7)
    await ctx.ask(PROMPTS.grantLease(a));
    ctx.charge(usage);
    const dek = await openClinicWrap(clinic.pair, a.interviewId, a.clinicWrap);
    return { rsa_wrapped_dek: toB64url(await wrapDekForLease(leaseKey, dek)) }; // zeruje dek
  },
};
```

- [ ] **Krok 7: Pełna tabela operacji w `src/ops/index.js`**

Zastąp cały plik:

```js
// Tabela operacji protokołu (spec B, „Operacje"). Klucze = nazwy `op`.
import { hello, lock } from "./basic.js";
import { createClinicKey, grantClinicAccess, loadClinicKey } from "./clinic.js";
import { addCredential, register, unlock } from "./doctor.js";
import { grantLease } from "./lease.js";
import { open } from "./open.js";

export const OPS = Object.freeze({
  hello,
  register,
  unlock,
  add_credential: addCredential,
  load_clinic_key: loadClinicKey,
  create_clinic_key: createClinicKey,
  grant_clinic_access: grantClinicAccess,
  open,
  grant_lease: grantLease,
  lock,
});
```

- [ ] **Krok 8: Uruchom — mają przejść**

Sprawdź obciążenie (pełny Vitest liczy kilkaset HPKE), potem:

Run: `npx vitest run`
Expected: PASS (wszystkie pliki).

- [ ] **Krok 9: Commit**

```bash
git add src/ops test/helpers/vault.js test/unit/ops-clinic.test.js test/unit/ops-open.test.js test/unit/ops-lease.test.js
git commit -m "feat(sejf): load_clinic_key, create_clinic_key, grant_clinic_access, open, grant_lease

Pełny łańcuch z wektorami: lekarz z sejf_v1.json otwiera grant kliniki z
bobik2_v1.json i jej pola (Sealed, SealedToClinic, przypadki negatywne).
Limit sprawdzany przed odszyfrowaniem, auto-blokada locked/limit, idle,
max_age; grant_lease liczy się jako otwarcie wywiadu po zatwierdzeniu.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 9: Sejf w przeglądarce — filtr rodzica, UI, konfiguracja dev/E2E, P-4, P-5

**Files:**
- Create: `src/parent.js`, `src/ui.js`, `scripts/dev-config.mjs`, `test/e2e/helpers.js`, `test/e2e/protocol.spec.js`
- Modify: `src/config.js` (`VERSION = "0.2.0"`, znaczniki originów), `src/vault.js` (całość), `src/index.html`, `src/vault.css`, `scripts/serve.mjs`, `playwright.config.js`, `test/e2e/panel/index.html`, `test/e2e/panel/panel.js`, `test/e2e/demo.spec.js:2,7`
- Delete: `test/e2e/hello.spec.js` (zastąpiony przez `protocol.spec.js`)
- Test: `test/unit/parent.test.js`, `test/unit/dev-config.test.js`, `test/unit/no-html-sinks.test.js`, `test/e2e/protocol.spec.js`

**Interfaces:**
- Consumes: `createVault` i kontrakt UI (zadanie 7), `statusText`/`formatCounters` (zadanie 6), istniejące `browserOk`, `fetchRevoked`, `prfSupport`.
- Produces:
  - `src/parent.js`: `isTopLevel(win) → boolean`, `acceptMessage(event, win, allowedOrigins) → boolean` (P6).
  - `src/ui.js`: `createUi(document) → {ask(prompt), cancel(code), render(view), onLock(fn)}`; elementy `#status`, `#fingerprint`, `#counter`, `#prompt`, `#prompt-title`, `#prompt-lines`, `#prompt-ok`, `#prompt-cancel`, `#lock` („Zablokuj"); `body[data-state]`.
  - `scripts/dev-config.mjs`: `DEV_PARENT_ORIGINS = ["http://127.0.0.1:8000", "http://localhost:8000"]`, `rewriteParentOrigins(text, origins) → string`.
  - `scripts/serve.mjs`: `node scripts/serve.mjs <port> <host> <prefiks>=<katalog>… [--dev-config | --parent-origins=a,b]` — kontrakt dla B3 (`--parent-origins=http://localhost:<port live_server>`).
  - `playwright.config.js`: eksporty `PANEL`, `FOREIGN_PANEL`, `VAULT`, `VAULT_PATH`.
  - Atrapa panelu: `?vault_path=/vX.Y.Z/` (wymagane), `?no_allow=1`; `window.vaultCall(op, args, timeoutMs = 120000) → Promise<envelope | {timeout: true}>`, `window.vaultEvents: Array<{v, event, reason}>`, `window.vaultReady`.
  - `test/e2e/helpers.js`: `AUTH_OPTS`, `openPanel(page, {base = PANEL, noAllow = false})`, `call(page, op, args, timeoutMs)`, `vaultFrame(page)`, `button(page, name)`, `clickInVault(page, name)`, `vaultFrameHandle(page)`.

- [ ] **Krok 1: Testy jednostkowe, które mają paść**

`test/unit/parent.test.js`:

```js
import { describe, expect, it } from "vitest";
import { acceptMessage, isTopLevel } from "../../src/parent.js";

const PANEL = "http://127.0.0.1:8000";
const DEV = "http://localhost:8000";

function win({ ancestors } = {}) {
  const w = { parent: {}, location: {} };
  if (ancestors) w.location.ancestorOrigins = ancestors;
  return w;
}

describe("filtr rodzica (rozstrzygnięcie 9, P6, V-3, Review Focus 4)", () => {
  it("rodzic z listy -> przyjęte", () => {
    const w = win();
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(true);
  });

  it.each([
    ["obcy origin", (w) => ({ source: w.parent, origin: "https://evil.example" })],
    ['origin "null" (sandbox, data:)', (w) => ({ source: w.parent, origin: "null" })],
    ["źródło inne niż rodzic (popup, inna ramka)", () => ({ source: {}, origin: PANEL })],
  ])("%s -> odrzucone", (_name, makeEvent) => {
    const w = win();
    expect(acceptMessage(makeEvent(w), w, [PANEL])).toBe(false);
  });

  it("ancestorOrigins[0] inny niż event.origin -> odrzucone (Chromium)", () => {
    const w = win({ ancestors: [DEV] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL, DEV])).toBe(false);
  });

  it("ancestorOrigins[0] === event.origin -> przyjęte", () => {
    const w = win({ ancestors: [PANEL] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(true);
  });

  it('ancestorOrigins zamaskowane ("null", referrerpolicy=no-referrer) -> rozstrzyga event.origin', () => {
    const w = win({ ancestors: ["null"] });
    expect(acceptMessage({ source: w.parent, origin: PANEL }, w, [PANEL])).toBe(true);
    expect(acceptMessage({ source: w.parent, origin: "https://evil.example" }, w, [PANEL])).toBe(false);
  });

  it("isTopLevel: window.parent === window", () => {
    const top = {};
    top.parent = top;
    expect(isTopLevel(top)).toBe(true);
    expect(isTopLevel(win())).toBe(false);
  });
});
```

`test/unit/dev-config.test.js`:

```js
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { DEV_PARENT_ORIGINS, rewriteParentOrigins } from "../../scripts/dev-config.mjs";
import { ALLOWED_PARENT_ORIGINS, VERSION } from "../../src/config.js";

const SRC = readFileSync(new URL("../../src/config.js", import.meta.url), "utf8");

// Podmieniony config jako prawdziwy moduł ES (plik tymczasowy — bez zależności od obsługi data: URL).
function load(text) {
  const file = join(mkdtempSync(join(tmpdir(), "sejf-config-")), "config.mjs");
  writeFileSync(file, text);
  return import(pathToFileURL(file).href);
}

describe("originy panelu: produkcja i podmiana dev/E2E (rozstrzygnięcie 11, P9, P12)", () => {
  it("VERSION 0.2.0; lista produkcyjna bez zmian względem 0.1.0 (odstępstwo P12)", () => {
    expect(VERSION).toBe("0.2.0");
    expect(ALLOWED_PARENT_ORIGINS).toEqual(["http://127.0.0.1:8000"]);
    expect(Object.isFrozen(ALLOWED_PARENT_ORIGINS)).toBe(true);
  });

  it("--dev-config: atrapa panelu i dev bobik-2; VERSION bez zmian", async () => {
    const mod = await load(rewriteParentOrigins(SRC, DEV_PARENT_ORIGINS));
    expect(mod.ALLOWED_PARENT_ORIGINS).toEqual(["http://127.0.0.1:8000", "http://localhost:8000"]);
    expect(mod.VERSION).toBe(VERSION);
  });

  it("--parent-origins: dowolna lista (np. live_server B3)", async () => {
    const mod = await load(rewriteParentOrigins(SRC, ["http://localhost:8123"]));
    expect(mod.ALLOWED_PARENT_ORIGINS).toEqual(["http://localhost:8123"]);
  });

  it("brak znaczników albo dwa bloki -> błąd", () => {
    expect(() => rewriteParentOrigins("export const X = 1;\n", DEV_PARENT_ORIGINS)).toThrow(/parent-origins/);
    expect(() => rewriteParentOrigins(SRC + SRC, DEV_PARENT_ORIGINS)).toThrow(/parent-origins/);
  });

  it("niepoprawny origin -> błąd", () => {
    for (const bad of ["javascript:alert(1)", "http://localhost:8000/", "https://a.example/x", '"),alert(1),("']) {
      expect(() => rewriteParentOrigins(SRC, [bad])).toThrow(/origin/);
    }
  });
});
```

`test/unit/no-html-sinks.test.js`:

```js
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { walk } from "../../scripts/sums.mjs";

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'";
const files = (await walk("src")).filter((f) => !f.split(/[\\/]/).includes("vendor"));

it("kod sejfu nie wstawia HTML-a ani nie wykonuje tekstu (Review Focus 2)", () => {
  const offenders = [];
  for (const f of files.filter((f) => f.endsWith(".js"))) {
    const text = readFileSync(f, "utf8");
    for (const re of [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/, /document\.write/, /\beval\(/, /new Function\(/]) {
      if (re.test(text)) offenders.push(`${f}: ${re}`);
    }
  }
  expect(offenders).toEqual([]);
});

it("strony sejfu: CSP z specu, bez skryptów, stylów i handlerów inline", () => {
  const offenders = [];
  for (const f of files.filter((f) => f.endsWith(".html"))) {
    const text = readFileSync(f, "utf8");
    if (!text.includes(`content="${CSP}"`)) offenders.push(`${f}: CSP`);
    if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(text)) offenders.push(`${f}: <script> bez src`);
    if (/\son[a-z]+\s*=/i.test(text)) offenders.push(`${f}: atrybut on…`);
    if (/\sstyle\s*=/i.test(text)) offenders.push(`${f}: atrybut style`);
  }
  expect(offenders).toEqual([]);
});
```

Run: `npx vitest run test/unit/parent.test.js test/unit/dev-config.test.js test/unit/no-html-sinks.test.js`
Expected: FAIL (`parent.js`, `dev-config.mjs` nie istnieją; `VERSION` to `0.1.0`). `no-html-sinks.test.js` PASS już teraz (pilnuje kolejnych kroków).

- [ ] **Krok 2: `src/parent.js`**

```js
// Kto może rozmawiać z sejfem (spec B, rozstrzygnięcie 9; decyzja planu P6).
// frame-ancestors nie działa w <meta>, a GitHub Pages nie daje nagłówków — stąd weryfikacja w JS.

export const isTopLevel = (win) => win.parent === win;

export function acceptMessage(event, win, allowedOrigins) {
  if (event.source !== win.parent) return false;
  if (!allowedOrigins.includes(event.origin)) return false;
  // Chromium: ancestorOrigins[0] = origin rodzica. "null" = zamaskowany przez referrerpolicy
  // iframe'a (B2 osadza z no-referrer) — wtedy, jak w Firefoksie, rozstrzyga event.origin.
  const ancestors = win.location.ancestorOrigins;
  if (ancestors && ancestors.length > 0 && ancestors[0] !== "null" && ancestors[0] !== event.origin) return false;
  return true;
}
```

- [ ] **Krok 3: `src/config.js` i `scripts/dev-config.mjs`**

`src/config.js` (cały plik):

```js
// Konfiguracja sejfu zaszyta w kodzie. Zmiana = nowy release.

export const VERSION = "0.2.0";

// Origin sejfu: https://bobik-2.github.io (organizacja GitHub bobik-2),
// RP ID WebAuthn = "bobik-2.github.io" (w kodzie location.hostname).

// Originy panelu bobik-2, którym sejf odpowiada na postMessage (rozstrzygnięcie 11).
// TODO przed użyciem produkcyjnym (README, „Przed użyciem produkcyjnym"): dopisać hosty
// produkcyjne panelu — nowy release. Blok między znacznikami podmienia przy serwowaniu
// scripts/serve.mjs --dev-config (dev i E2E); build z tagów go nie zmienia.
export const ALLOWED_PARENT_ORIGINS = Object.freeze([
  // <parent-origins>
  "http://127.0.0.1:8000", // atrapa panelu w testach E2E (decyzja planu P12)
  // </parent-origins>
]);
```

`scripts/dev-config.mjs`:

```js
// Podmiana listy originów panelu w src/config.js przy lokalnym serwowaniu (dev, E2E, B3).
// Nigdy w buildzie: dist/ powstaje z `git archive` podpisanych tagów (rozstrzygnięcia 11 i 12).

// Atrapa panelu (testy sejfu) i dev bobik-2 (docker compose / runserver na :8000).
export const DEV_PARENT_ORIGINS = Object.freeze(["http://127.0.0.1:8000", "http://localhost:8000"]);

const OPEN = "// <parent-origins>";
const CLOSE = "// </parent-origins>";
const BLOCK = /(\/\/ <parent-origins>\n)[\s\S]*?(\n[ \t]*\/\/ <\/parent-origins>)/;
const ORIGIN = /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/;

export function rewriteParentOrigins(text, origins) {
  if (text.split(OPEN).length !== 2 || text.split(CLOSE).length !== 2 || !BLOCK.test(text)) {
    throw new Error("src/config.js: oczekiwano dokładnie jednego bloku // <parent-origins> … // </parent-origins>");
  }
  for (const origin of origins) {
    if (!ORIGIN.test(origin)) throw new Error(`nieprawidłowy origin panelu: ${origin}`);
  }
  const lines = origins.map((o) => `  ${JSON.stringify(o)}, // dev/E2E (scripts/serve.mjs)`).join("\n");
  return text.replace(BLOCK, (_match, open, close) => `${open}${lines}${close}`);
}
```

- [ ] **Krok 4: `scripts/serve.mjs` z `--dev-config` / `--parent-origins`**

Zastąp cały plik:

```js
// Minimalny serwer statyczny do testów i dev (bez zależności).
// Użycie: node scripts/serve.mjs <port> <host> <prefiks>=<katalog> [...] [--dev-config | --parent-origins=a,b]
// --dev-config / --parent-origins podmieniają przy serwowaniu listę originów panelu w src/config.js
// (rozstrzygnięcie 11). Build tego nie widzi: dist/ powstaje z `git archive` tagów.
import { readFileSync } from "node:fs";
import { readFile, stat } from "node:fs/promises";
import { createServer } from "node:http";
import { extname, join, normalize, resolve } from "node:path";
import { DEV_PARENT_ORIGINS, rewriteParentOrigins } from "./dev-config.mjs";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
};

let parentOrigins = null;
const positional = [];
for (const arg of process.argv.slice(2)) {
  if (arg === "--dev-config") parentOrigins = DEV_PARENT_ORIGINS;
  else if (arg.startsWith("--parent-origins=")) parentOrigins = arg.slice("--parent-origins=".length).split(",");
  else if (arg.startsWith("--")) throw new Error(`serve.mjs: nieznana opcja ${arg}`);
  else positional.push(arg);
}
const [port, host, ...mountArgs] = positional;
const CONFIG = resolve("src/config.js");
// Sprawdzenie od razu: zły origin albo brak znaczników kończy start, zamiast psuć pojedyncze żądania.
if (parentOrigins) rewriteParentOrigins(readFileSync(CONFIG, "utf8"), parentOrigins);

// Najdłuższy prefiks wygrywa.
const mounts = mountArgs
  .map((m) => {
    const [prefix, dir] = m.split("=");
    return { prefix, dir: resolve(dir) };
  })
  .sort((a, b) => b.prefix.length - a.prefix.length);

createServer(async (req, res) => {
  const path = decodeURIComponent(new URL(req.url, "http://x").pathname);
  const mount = mounts.find((m) => path === m.prefix || path.startsWith(m.prefix.endsWith("/") ? m.prefix : m.prefix + "/"));
  if (!mount) return notFound(res);
  let file = normalize(join(mount.dir, path.slice(mount.prefix.length)));
  if (!file.startsWith(mount.dir)) return notFound(res);
  let body;
  try {
    if ((await stat(file)).isDirectory()) file = join(file, "index.html");
    body = await readFile(file);
  } catch (e) {
    // ENOENT/ENOTDIR: brak pliku pod ścieżką; EISDIR: katalog — dla klienta 404.
    if (e?.code === "ENOENT" || e?.code === "ENOTDIR" || e?.code === "EISDIR") return notFound(res);
    throw e;
  }
  if (parentOrigins && file === CONFIG) body = rewriteParentOrigins(body.toString("utf8"), parentOrigins);
  res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
  res.end(body);
}).listen(Number(port), host);

function notFound(res) {
  res.writeHead(404);
  res.end();
}
```

Run: `npx vitest run test/unit/parent.test.js test/unit/dev-config.test.js test/unit/no-html-sinks.test.js`
Expected: PASS.

- [ ] **Krok 5: UI sejfu — `src/index.html`, `src/vault.css`, `src/ui.js`**

`src/index.html` (cały plik):

```html
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sejf kluczy bobik</title>
<link rel="stylesheet" href="vault.css">
<script type="module" src="vault.js"></script>
</head>
<body>
<main id="vault">
  <p id="status" role="status">Sejf zablokowany</p>
  <p id="fingerprint" hidden></p>
  <p id="counter" hidden></p>
  <section id="prompt" hidden aria-labelledby="prompt-title">
    <h2 id="prompt-title"></h2>
    <div id="prompt-lines"></div>
    <div class="actions">
      <button id="prompt-ok" type="button"></button>
      <button id="prompt-cancel" type="button"></button>
    </div>
  </section>
  <button id="lock" type="button" hidden>Zablokuj</button>
</main>
</body>
</html>
```

`src/vault.css` (cały plik):

```css
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { margin: 0; padding: 12px; }
[hidden] { display: none !important; }
#status { font-weight: 600; margin: 0 0 8px; }
body[data-state="refusing"] #status { color: #b00020; }
#fingerprint, #counter { font-family: ui-monospace, monospace; margin: 4px 0; }
#prompt { border: 2px solid currentColor; border-radius: 6px; padding: 8px 12px; margin: 8px 0; }
#prompt h2 { font-size: 1.05rem; margin: 0 0 6px; }
#prompt-lines p { margin: 4px 0; overflow-wrap: anywhere; }
.actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 8px; }
button { font: inherit; padding: 6px 12px; }
```

`src/ui.js`:

```js
// UI sejfu: potwierdzenia, licznik, odcisk, ekrany blokady. Teksty od panelu (etykiety, study_code)
// są nieuwierzytelnione (B-R8) i trafiają do DOM wyłącznie przez textContent (Review Focus 2).
import { VaultError } from "./errors.js";
import { formatCounters, statusText } from "./prompts.js";

export function createUi(doc) {
  const el = (id) => {
    const node = doc.getElementById(id);
    if (!node) throw new Error(`ui: brak #${id} w index.html`);
    return node;
  };
  const status = el("status");
  const fingerprint = el("fingerprint");
  const counter = el("counter");
  const prompt = el("prompt");
  const title = el("prompt-title");
  const lines = el("prompt-lines");
  const ok = el("prompt-ok");
  const cancel = el("prompt-cancel");
  const lock = el("lock");
  let pending = null;

  function settle(finish) {
    if (!pending) return;
    const current = pending;
    pending = null;
    prompt.hidden = true;
    finish(current);
  }
  ok.addEventListener("click", () => settle((p) => p.resolve()));
  cancel.addEventListener("click", () => settle((p) => p.reject(new VaultError("user_rejected"))));

  return {
    ask(spec) {
      if (pending) return Promise.reject(new VaultError("busy"));
      title.textContent = spec.title;
      lines.replaceChildren(
        ...spec.lines.map((text) => {
          const p = doc.createElement("p");
          p.textContent = text;
          return p;
        }),
      );
      ok.textContent = spec.confirm;
      cancel.textContent = spec.cancel;
      prompt.hidden = false;
      ok.focus();
      return new Promise((resolve, reject) => {
        pending = { resolve, reject };
      });
    },
    cancel(code) {
      settle((p) => p.reject(new VaultError(code)));
    },
    render(view) {
      status.textContent = statusText(view);
      fingerprint.hidden = !view.fingerprint;
      fingerprint.textContent = view.fingerprint ? `Odcisk Twojego klucza: ${view.fingerprint}` : "";
      counter.hidden = !view.counters;
      counter.textContent = view.counters ? formatCounters(view.counters) : "";
      lock.hidden = view.state !== "unlocked";
      doc.body.dataset.state = view.state;
    },
    onLock(fn) {
      lock.addEventListener("click", fn);
    },
  };
}
```

- [ ] **Krok 6: `src/vault.js` — spięcie z oknem**

Zastąp cały plik:

```js
// Spięcie rdzenia sejfu z oknem przeglądarki: filtr rodzica, UI, zegar blokady.
import { browserOk } from "./browser.js";
import { ALLOWED_PARENT_ORIGINS } from "./config.js";
import { createVault } from "./core.js";
import { acceptMessage, isTopLevel } from "./parent.js";
import { fetchRevoked } from "./revocation.js";
import { createUi } from "./ui.js";
import { prfSupport } from "./webauthn.js";

const TICK_MS = 5_000;
const ui = createUi(document);

if (isTopLevel(window)) {
  // Rozstrzygnięcie 9: sejf otwarty jako strona najwyższego poziomu nie przyjmuje wiadomości.
  ui.render({ state: "refusing", refusal: "top_level", fingerprint: null, counters: null });
} else {
  let parentOrigin = null;
  const vault = createVault({
    ready: fetchRevoked(fetch, new URL("../revoked.json", import.meta.url)),
    browserOk: browserOk(window),
    prf: prfSupport(window),
    credentials: navigator.credentials,
    rpId: location.hostname,
    ui,
    emit: (msg) => {
      // Zdarzenia tylko do rodzica, który już przeszedł filtr — nigdy "*".
      if (parentOrigin) window.parent.postMessage(msg, parentOrigin);
    },
  });
  ui.onLock(() => vault.lock("user"));
  setInterval(() => vault.tick(), TICK_MS);
  window.addEventListener("message", async (event) => {
    if (!acceptMessage(event, window, ALLOWED_PARENT_ORIGINS)) return;
    parentOrigin = event.origin;
    const response = await vault.respond(event.data);
    event.source.postMessage(response, event.origin);
  });
}
```

- [ ] **Krok 7: Atrapa panelu jak w B2, konfiguracja Playwright, pomocnicy E2E**

`test/e2e/panel/index.html` (cały plik):

```html
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>Atrapa panelu bobik-2</title>
<script type="module" src="panel.js"></script>
</head>
<body>
<!-- Atrybuty jak w bobik-2 dashboard/templates/dashboard/vault/_iframe.html (allow + referrerpolicy). -->
<iframe id="vault" title="Sejf kluczy"
  allow="publickey-credentials-get; publickey-credentials-create"
  referrerpolicy="no-referrer"
  width="560" height="460"></iframe>
</body>
</html>
```

`test/e2e/panel/panel.js` (cały plik):

```js
// Atrapa panelu bobik-2: osadza sejf (?vault_path=/vX.Y.Z/, opcjonalnie ?no_allow=1) i wystawia
// testom window.vaultCall(op, args, timeoutMs) oraz window.vaultEvents (zdarzenia sejfu).
const params = new URLSearchParams(location.search);
const VAULT_ORIGIN = params.get("vault_origin") ?? "http://localhost:8001";
const VAULT_PATH = params.get("vault_path");
if (!VAULT_PATH) throw new Error("atrapa panelu: brak ?vault_path=/vX.Y.Z/");

const frame = document.getElementById("vault");
if (params.get("no_allow") === "1") frame.removeAttribute("allow");
const pending = new Map();
let seq = 0;
window.vaultEvents = [];

window.addEventListener("message", (event) => {
  if (event.origin !== VAULT_ORIGIN || event.source !== frame.contentWindow) return;
  const msg = event.data;
  if (msg && typeof msg.event === "string") {
    window.vaultEvents.push(msg);
    return;
  }
  const resolve = pending.get(msg?.id);
  if (!resolve) return;
  pending.delete(msg.id);
  resolve(msg);
});

window.vaultReady = new Promise((resolve) => frame.addEventListener("load", resolve, { once: true }));
frame.src = VAULT_ORIGIN + VAULT_PATH;

window.vaultCall = async (op, args = {}, timeoutMs = 120_000) => {
  await window.vaultReady;
  const id = `m${++seq}`;
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      resolve({ timeout: true });
    }, timeoutMs);
    pending.set(id, (msg) => {
      clearTimeout(timer);
      resolve(msg);
    });
    frame.contentWindow.postMessage({ v: 1, id, op, ...args }, VAULT_ORIGIN);
  });
};
```

`playwright.config.js` (cały plik):

```js
import { defineConfig, devices } from "@playwright/test";
import { VERSION } from "./src/config.js";

// Sejf na localhost (poprawny RP ID), panel na 127.0.0.1 — inne originy i inne site'y, jak w
// produkcji. Drugi panel (8002) jest spoza ALLOWED_PARENT_ORIGINS (test „obcy origin").
export const PANEL = "http://127.0.0.1:8000";
export const FOREIGN_PANEL = "http://127.0.0.1:8002";
export const VAULT = "http://localhost:8001";
export const VAULT_PATH = `/v${VERSION}/`;

export default defineConfig({
  testDir: "test/e2e",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? "github" : "list",
  use: { baseURL: PANEL },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    // WebKit tylko do sprawdzenia blokady Safari (D13).
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
  webServer: [
    {
      command: "node scripts/serve.mjs 8000 127.0.0.1 /=test/e2e/panel",
      url: `${PANEL}/`,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: "node scripts/serve.mjs 8002 127.0.0.1 /=test/e2e/panel",
      url: `${FOREIGN_PANEL}/`,
      reuseExistingServer: !process.env.CI,
    },
    {
      command: `node scripts/serve.mjs 8001 localhost /=public /v${VERSION}=src --dev-config`,
      url: `${VAULT}/revoked.json`,
      reuseExistingServer: !process.env.CI,
    },
  ],
});
```

`test/e2e/helpers.js`:

```js
// Pomocnicy E2E: atrapa panelu, wywołania sejfu, przyciski w ramce, wirtualne authenticatory CDP.
import { expect } from "@playwright/test";
import { PANEL, VAULT, VAULT_PATH } from "../../playwright.config.js";

export const AUTH_OPTS = {
  protocol: "ctap2",
  ctap2Version: "ctap2_1",
  transport: "usb",
  hasResidentKey: true,
  hasUserVerification: true,
  isUserVerified: true,
  hasPrf: true,
  automaticPresenceSimulation: true,
};

export async function openPanel(page, { base = PANEL, noAllow = false } = {}) {
  const query = new URLSearchParams({ vault_path: VAULT_PATH });
  if (noAllow) query.set("no_allow", "1");
  await page.goto(`${base}/?${query}`);
  await page.evaluate(() => window.vaultReady);
}

export const call = (page, op, args = {}, timeoutMs = 120_000) =>
  page.evaluate(([o, a, t]) => window.vaultCall(o, a, t), [op, args, timeoutMs]);

export const vaultFrame = (page) => page.frameLocator("#vault");
export const button = (page, name) => vaultFrame(page).getByRole("button", { name, exact: true });
export const clickInVault = (page, name) => button(page, name).click();

// Ramka sejfu jako Frame (do evaluate w originie sejfu).
export function vaultFrameHandle(page) {
  const frame = page.frames().find((f) => f.url().startsWith(VAULT));
  expect(frame, "ramka sejfu").toBeTruthy();
  return frame;
}
```

`test/e2e/demo.spec.js` — zastąp linie importu i adresu demo:

```js
import { expect, test } from "@playwright/test";
import { VAULT, VAULT_PATH } from "../../playwright.config.js";
```

```js
const DEMO = `${VAULT}${VAULT_PATH}demo.html`;
```

Usuń stary test protokołu:

```bash
git rm test/e2e/hello.spec.js
```

- [ ] **Krok 8: E2E protokołu (P-4, P-5, filtr rodzica)**

`test/e2e/protocol.spec.js`:

```js
import { expect, test } from "@playwright/test";
import { FOREIGN_PANEL, VAULT, VAULT_PATH } from "../../playwright.config.js";
import { VERSION } from "../../src/config.js";
import { call, openPanel, vaultFrame, vaultFrameHandle } from "./helpers.js";

test("hello: wersja, stan, przeglądarka (moduły i wendorowane HPKE ładują się pod CSP)", async ({ page, browserName }) => {
  await openPanel(page);
  const res = await call(page, "hello");
  const blocked = browserName === "webkit";
  expect(res).toMatchObject({ v: 1, ok: true, result: { version: VERSION, revoked: false, browser_ok: !blocked, state: blocked ? "refusing" : "locked" } });
  expect([true, false, null]).toContain(res.result.prf);
});

test("P-4 / P-3: panel spoza listy originów nie dostaje żadnej odpowiedzi", async ({ page }) => {
  await openPanel(page, { base: FOREIGN_PANEL });
  expect(await call(page, "hello", {}, 2_000)).toEqual({ timeout: true });
});

test("P-4: stan locked odrzuca operacje wymagające odblokowania", async ({ page, browserName }) => {
  test.skip(browserName === "webkit", "WebKit jest w stanie refusing (P-5)");
  await openPanel(page);
  expect(await call(page, "open", { interviews: [], items: [] })).toMatchObject({ ok: false, error: "locked" });
  expect(await call(page, "lock")).toMatchObject({ ok: true, result: {} });
  await expect(vaultFrame(page).locator("#status")).toHaveText("Sejf zablokowany");
});

test("P-5: WebKit — register i unlock kończą się browser_blocked, ekran blokady", async ({ page, browserName }) => {
  test.skip(browserName !== "webkit", "blokada Safari dotyczy wyłącznie WebKit (D13)");
  await openPanel(page);
  expect(await call(page, "register", { doctor_id: 17, display_name: "dr Anna Nowak" })).toMatchObject({ ok: false, error: "browser_blocked" });
  expect(await call(page, "unlock", { doctor_id: 17, public_key_der: "AAAA", credentials: [] })).toMatchObject({ ok: false, error: "browser_blocked" });
  await expect(vaultFrame(page).locator("#status")).toContainText("Safari");
});

test("sejf otwarty jako strona najwyższego poziomu odmawia pracy (rozstrzygnięcie 9)", async ({ page }) => {
  await page.goto(`${VAULT}${VAULT_PATH}`);
  await expect(page.locator("#status")).toHaveText("Sejf działa wyłącznie osadzony w panelu bobik-2.");
});

test("Chromium: ancestorOrigins w iframe z referrerpolicy=no-referrer nie blokuje rodzica (P6)", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "location.ancestorOrigins istnieje tylko w Chromium");
  await openPanel(page);
  const ancestors = await vaultFrameHandle(page).evaluate(() => Array.from(location.ancestorOrigins));
  console.log(`ancestorOrigins w ramce sejfu: ${JSON.stringify(ancestors)}`);
  expect([["http://127.0.0.1:8000"], ["null"]]).toContainEqual(ancestors);
  expect(await call(page, "hello")).toMatchObject({ ok: true });
});
```

- [ ] **Krok 9: Uruchom E2E i Vitest**

Sprawdź obciążenie (Global Constraints). Jeśli porty 8000–8002 trzyma stary serwer z poprzedniego przebiegu **tej** sesji (`lsof -i :8001`), zatrzymaj go — `reuseExistingServer` użyłby serwera bez `--dev-config`.

Run: `npx vitest run && npx playwright test`
Expected: PASS we wszystkich trzech projektach (`hello`, obcy origin, `locked` w Chromium i Firefoksie, `browser_blocked` w WebKit, strona najwyższego poziomu, ancestorOrigins w Chromium, demo). Zapisz wartość `ancestorOrigins` z logu testu — trafi do README w zadaniu 12. Jeśli test ancestorOrigins pokaże inną wartość niż obie dozwolone, **zatrzymaj się i zgłoś** (to decyzja P6, nie poprawka w teście).

- [ ] **Krok 10: Commit**

```bash
git add src/parent.js src/ui.js src/config.js src/vault.js src/index.html src/vault.css scripts/dev-config.mjs scripts/serve.mjs playwright.config.js test/e2e test/unit/parent.test.js test/unit/dev-config.test.js test/unit/no-html-sinks.test.js
git commit -m "feat(sejf): UI i spięcie z przeglądarką, filtr rodzica, config dev/E2E; wersja 0.2.0

Filtr: source === parent, origin z listy, ancestorOrigins (z maskowaniem
\"null\" przy referrerpolicy=no-referrer). Ekrany: zablokowany, odblokowany,
unieważniona wersja, Safari, strona najwyższego poziomu; potwierdzenia przez
textContent. serve.mjs --dev-config / --parent-origins podmienia originy przy
serwowaniu. E2E: P-4 (Firefox), P-5 (WebKit), obcy origin.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 10: Playwright P-1, P-2, P-3 (Chromium, wirtualne authenticatory CDP)

**Files:**
- Create: `test/e2e/shims.js`, `test/e2e/flows.spec.js`, `test/e2e/limits.spec.js`
- Modify: `test/e2e/helpers.js` (authenticatory, rejestracja, odblokowanie, grant kliniki z bobik2_v1.json, zegar)

**Interfaces:**
- Consumes: atrapa panelu i pomocnicy z zadania 9; `sealClinicGrant` (zadanie 3), `hpkeSeal` (zadanie 1), `importP256Public` (zadanie 2), wektory z `test/helpers/vectors.js`; etykiety przycisków z zadania 6.
- Produces (w `test/e2e/helpers.js`): `authenticators(context, page) → {insert() → id, remove(id)}`, `register(page, auth, {doctorId, displayName, secondTouch = false}) → result`, `unlock(page, reg, doctorId) → result`, `grantBobik2Clinic(page, reg, doctorId)`, `fakeInterviews(n)`, `shiftClock(page, ms)`; w `test/e2e/shims.js`: `stripPrfAtCreate`, `shiftableClock` (P13).

- [ ] **Krok 1: Skrypty testowe i pomocnicy**

`test/e2e/shims.js`:

```js
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
```

Dopisz do `test/e2e/helpers.js` (importy na górę, funkcje na koniec):

```js
import { toB64url } from "../../src/b64.js";
import { random, sha256Hex, utf8 } from "../../src/bytes.js";
import { sealClinicGrant } from "../../src/crypto/clinic.js";
import { dekInfo } from "../../src/crypto/context.js";
import { hpkeSeal } from "../../src/crypto/hpke.js";
import { importP256Public } from "../../src/crypto/keys.js";
import { BOBIK2, b } from "../helpers/vectors.js";
```

```js
// Wirtualne YubiKeye na sesji CDP strony — obsługują też żądania z ramki sejfu (spike 4).
export async function authenticators(context, page) {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable", { enableUI: false });
  return {
    insert: async () => (await cdp.send("WebAuthn.addVirtualAuthenticator", { options: AUTH_OPTS })).authenticatorId,
    remove: (authenticatorId) => cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId }),
  };
}

// Rejestracja jak u lekarza: klucz 1 → (drugie dotknięcie) → wyjęcie, klucz 2 → (drugie dotknięcie).
export async function register(page, auth, { doctorId, displayName, secondTouch = false }) {
  const first = await auth.insert();
  const pending = call(page, "register", { doctor_id: doctorId, display_name: displayName });
  await clickInVault(page, "Zarejestruj klucz 1");
  if (secondTouch) await clickInVault(page, "Dotknij ponownie");
  await expect(button(page, "Zarejestruj klucz 2")).toBeVisible();
  await auth.remove(first);
  await auth.insert();
  await clickInVault(page, "Zarejestruj klucz 2");
  if (secondTouch) await clickInVault(page, "Dotknij ponownie");
  const res = await pending;
  expect(res, JSON.stringify(res)).toMatchObject({ ok: true });
  return res.result;
}

// Odblokowanie kluczem, który jest włożony (po register: drugi).
export async function unlock(page, reg, doctorId) {
  const pending = call(page, "unlock", { doctor_id: doctorId, public_key_der: reg.public_key_der, credentials: reg.credentials });
  await clickInVault(page, "Odblokuj");
  const res = await pending;
  expect(res, JSON.stringify(res)).toMatchObject({ ok: true });
  return res.result;
}

// Grant F4 klucza kliniki z bobik2_v1.json dla świeżo zarejestrowanego lekarza — liczony w Node,
// tak jak zrobiłby to inny posiadacz klucza kliniki (grant_clinic_access); potem load_clinic_key.
export async function grantBobik2Clinic(page, reg, doctorId) {
  const doctorKey = await importP256Public(b(reg.public_key_der));
  const grant = await sealClinicGrant(doctorKey, {
    clinicId: BOBIK2.clinic_id,
    doctorId,
    clinicSpkiHex: await sha256Hex(b(BOBIK2.clinic.public_key_spki_der)),
    pkcs8: b(BOBIK2.clinic.private_key_pkcs8_der),
  });
  const res = await call(page, "load_clinic_key", {
    clinic_id: BOBIK2.clinic_id,
    clinic_key_id: BOBIK2.clinic_key_id,
    clinic_public_key_der: BOBIK2.clinic.public_key_spki_der,
    wrapped_private: toB64url(grant),
  });
  expect(res, JSON.stringify(res)).toMatchObject({ ok: true, result: { fingerprint: BOBIK2.clinic.fingerprint } });
}

// Wywiady pod kluczem kliniki z bobik2_v1.json, z losowym DEK — do testu limitu.
export async function fakeInterviews(n) {
  const pub = await importP256Public(b(BOBIK2.clinic.public_key_spki_der));
  const out = [];
  for (let i = 0; i < n; i++) {
    const id = crypto.randomUUID();
    const wrap = await hpkeSeal(pub, utf8(dekInfo(id)), random(32));
    out.push({ interview_id: id, interview_key_id: crypto.randomUUID(), clinic_key_id: BOBIK2.clinic_key_id, clinic_wrap: toB64url(wrap) });
  }
  return out;
}

export const shiftClock = (page, ms) => vaultFrameHandle(page).evaluate((delta) => window.__bobikShiftClock(delta), ms);
```

- [ ] **Krok 2: Testy P-1 i P-2**

`test/e2e/flows.spec.js`:

```js
import { expect, test } from "@playwright/test";
import { toB64url } from "../../src/b64.js";
import { BOBIK2, b, bobik2ExpectedValues, bobik2LeaseArgs, bobik2OpenRequest } from "../helpers/vectors.js";
import { authenticators, call, clickInVault, grantBobik2Clinic, openPanel, register, unlock, vaultFrame, vaultFrameHandle } from "./helpers.js";
import { stripPrfAtCreate } from "./shims.js";

test.skip(({ browserName }) => browserName !== "chromium", "wirtualne authenticatory tylko przez CDP (Chromium) — B-R9");

test("P-1: rejestracja, odblokowanie, klucz kliniki, nadanie dostępu, odczyt, dzierżawa, blokada", async ({ page, context, browser }) => {
  test.setTimeout(120_000);
  const authA = await authenticators(context, page);
  await openPanel(page);
  const regA = await register(page, authA, { doctorId: 17, displayName: "dr Anna Nowak" });
  expect(await unlock(page, regA, 17)).toEqual({ fingerprint: regA.fingerprint });
  await expect(vaultFrame(page).locator("#fingerprint")).toContainText(regA.fingerprint);

  // create_clinic_key → load_clinic_key; etykieta z HTML-em pokazana dosłownie (Review Focus 2).
  const label = '<img src=x onerror="window.pwned=1">Klinika Testowa';
  const creating = call(page, "create_clinic_key", { clinic_id: 5, clinic_label: label });
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText(label);
  await expect(vaultFrame(page).locator("#prompt img")).toHaveCount(0);
  await clickInVault(page, "Załóż klucz");
  const created = await creating;
  expect(created).toMatchObject({ ok: true });
  const clinicKeyId = crypto.randomUUID();
  const loaded = await call(page, "load_clinic_key", {
    clinic_id: 5,
    clinic_key_id: clinicKeyId,
    clinic_public_key_der: created.result.clinic_public_key_der,
    wrapped_private: created.result.wrapped_private,
  });
  expect(loaded).toMatchObject({ ok: true, result: { clinic_key_id: clinicKeyId, fingerprint: created.result.fingerprint } });

  // Drugi lekarz w osobnym kontekście; nadający widzi w sejfie jego odcisk.
  const contextB = await browser.newContext();
  const pageB = await contextB.newPage();
  const authB = await authenticators(contextB, pageB);
  await openPanel(pageB);
  const regB = await register(pageB, authB, { doctorId: 18, displayName: "dr Piotr Zieliński" });
  const granting = call(page, "grant_clinic_access", {
    clinic_key_id: clinicKeyId,
    recipient_doctor_id: 18,
    recipient_label: "dr Piotr Zieliński",
    recipient_public_key_der: regB.public_key_der,
  });
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText(regB.fingerprint);
  await clickInVault(page, "Odcisk zgodny — nadaj dostęp");
  const granted = await granting;
  expect(granted).toMatchObject({ ok: true, result: { recipient_fingerprint: regB.fingerprint } });
  await unlock(pageB, regB, 18);
  const loadedB = await call(pageB, "load_clinic_key", {
    clinic_id: 5,
    clinic_key_id: clinicKeyId,
    clinic_public_key_der: created.result.clinic_public_key_der,
    wrapped_private: granted.result.wrapped_private,
  });
  expect(loadedB).toMatchObject({ ok: true, result: { fingerprint: created.result.fingerprint } });
  await contextB.close();

  // open danych z bobik2_v1.json (klucz kliniki z wektora, grant dla lekarza A).
  await grantBobik2Clinic(page, regA, 17);
  expect(await call(page, "open", bobik2OpenRequest())).toMatchObject({ ok: true, result: { values: bobik2ExpectedValues() } });
  await expect(vaultFrame(page).locator("#counter")).toContainText("Wywiady: 1/50 · wartości kliniki: 3/500"); // 2 pola STC + 1 przypadek negatywny

  // grant_lease: lekarz widzi wywiad, rodzaj i czas; DEK otwiera klucz dzierżawy.
  const leasing = call(page, "grant_lease", bobik2LeaseArgs());
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText("BOB-0001");
  await expect(vaultFrame(page).locator("#prompt-lines")).toContainText("7 dni");
  await clickInVault(page, "Zatwierdź");
  const leased = await leasing;
  expect(leased).toMatchObject({ ok: true });
  const priv = await crypto.subtle.importKey("pkcs8", b(BOBIK2.rsa_lease_key.private_key_pkcs8_der), { name: "RSA-OAEP", hash: "SHA-256" }, false, ["decrypt"]);
  const dek = new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, priv, b(leased.result.rsa_wrapped_dek)));
  expect(toB64url(dek)).toBe(BOBIK2.dek);

  // lock przyciskiem w sejfie → zdarzenie do panelu, klucze znikają.
  expect(await page.evaluate(() => window.vaultEvents)).toEqual([]);
  await clickInVault(page, "Zablokuj");
  await expect.poll(() => page.evaluate(() => window.vaultEvents)).toEqual([{ v: 1, event: "locked", reason: "user" }]);
  await expect(vaultFrame(page).locator("#status")).toHaveText("Sejf zablokowany");
  expect(await call(page, "open", bobik2OpenRequest())).toMatchObject({ ok: false, error: "locked" });
  expect(await vaultFrameHandle(page).evaluate(() => window.pwned)).toBeUndefined();
});

test("P-2: klucz bez PRF przy create() — drugie dotknięcie każdego klucza, potem unlock", async ({ page, context }) => {
  test.setTimeout(60_000);
  await context.addInitScript(stripPrfAtCreate);
  const auth = await authenticators(context, page);
  await openPanel(page);
  const reg = await register(page, auth, { doctorId: 17, displayName: "dr Anna Nowak", secondTouch: true });
  expect(await unlock(page, reg, 17)).toEqual({ fingerprint: reg.fingerprint });
});
```

- [ ] **Krok 3: Test P-3**

`test/e2e/limits.spec.js`:

```js
import { expect, test } from "@playwright/test";
import { authenticators, call, clickInVault, fakeInterviews, grantBobik2Clinic, openPanel, register, shiftClock, unlock, vaultFrame } from "./helpers.js";
import { shiftableClock } from "./shims.js";

test.skip(({ browserName }) => browserName !== "chromium", "wirtualne authenticatory tylko przez CDP (Chromium) — B-R9");

const FIVE_MIN = 5 * 60_000;

test("P-3: rate_limited w oknie, a 51. wywiad w sesji blokuje sejf (locked/limit)", async ({ page, context }) => {
  test.setTimeout(120_000);
  await context.addInitScript(shiftableClock);
  const auth = await authenticators(context, page);
  await openPanel(page);
  const reg = await register(page, auth, { doctorId: 17, displayName: "dr Anna Nowak" });
  await unlock(page, reg, 17);
  await grantBobik2Clinic(page, reg, 17);
  const interviews = await fakeInterviews(51);

  expect(await call(page, "open", { interviews: interviews.slice(0, 10), items: [] })).toMatchObject({ ok: true });
  expect(await call(page, "open", { interviews: [interviews[10]], items: [] })).toMatchObject({ ok: false, error: "rate_limited" });
  await expect(vaultFrame(page).locator("#counter")).toContainText("Wywiady: 10/50");
  for (let round = 1; round < 5; round++) {
    await shiftClock(page, FIVE_MIN);
    expect(await call(page, "open", { interviews: interviews.slice(round * 10, round * 10 + 10), items: [] })).toMatchObject({ ok: true });
  }
  expect(await page.evaluate(() => window.vaultEvents)).toEqual([]);
  await shiftClock(page, FIVE_MIN);
  expect(await call(page, "open", { interviews: [interviews[50]], items: [] })).toMatchObject({ ok: false, error: "limit_reached" });
  await expect.poll(() => page.evaluate(() => window.vaultEvents)).toEqual([{ v: 1, event: "locked", reason: "limit" }]);
  await expect(vaultFrame(page).locator("#status")).toHaveText("Sejf zablokowany");
  expect(await call(page, "open", { interviews: [], items: [] })).toMatchObject({ ok: false, error: "locked" });
});

test("P-3: iframe bez allow=publickey-credentials-* -> register kończy się not_allowed", async ({ page, context }) => {
  const auth = await authenticators(context, page);
  await auth.insert();
  await openPanel(page, { noAllow: true });
  const pending = call(page, "register", { doctor_id: 17, display_name: "dr Anna Nowak" });
  await clickInVault(page, "Zarejestruj klucz 1");
  expect(await pending).toMatchObject({ ok: false, error: "not_allowed" });
});
```

Wiadomość z obcego originu bez odpowiedzi (trzeci punkt P-3) pokrywa `protocol.spec.js` z zadania 9 we wszystkich przeglądarkach.

- [ ] **Krok 4: Uruchom**

Sprawdź obciążenie (Global Constraints), potem:

Run: `npx playwright test --project=chromium`
Expected: PASS (P-1, P-2, P-3 ×2 + testy z zadania 9 i demo).

Diagnoza, jeśli coś padnie (nie zmieniaj wtedy kodu sejfu „pod test"):
- P-2 nie pokazuje przycisku „Dotknij ponownie" → `addInitScript` nie dotarł do ramki cross-origin. Sprawdź `vaultFrameHandle(page).evaluate(() => PublicKeyCredential.prototype.getClientExtensionResults.toString())`; jeśli to kod natywny, zatrzymaj się i zgłoś.
- P-3 nie dochodzi do `limit_reached` po rundach → zegar nie przesunął się w ramce: `vaultFrameHandle(page).evaluate(() => typeof window.__bobikShiftClock)` musi dać `"function"`; w przeciwnym razie zatrzymaj się i zgłoś.

Potem pełny przebieg wszystkich projektów:

Run: `npx vitest run && npx playwright test`
Expected: PASS (Chromium, Firefox, WebKit; testy WebAuthn pomijane poza Chromium).

- [ ] **Krok 5: Commit**

```bash
git add test/e2e/shims.js test/e2e/flows.spec.js test/e2e/limits.spec.js test/e2e/helpers.js
git commit -m "test(e2e): P-1, P-2, P-3 — pełny przepływ sejfu na wirtualnych YubiKeyach

P-1: register (2 klucze) → unlock drugim → create/load klucza kliniki → grant
dla drugiego lekarza z odciskiem w sejfie → open danych bobik2_v1.json →
grant_lease → Zablokuj. P-2: brak PRF przy create() (shim) → drugie dotknięcie.
P-3: rate_limited, limit sesji → locked/limit, iframe bez allow → not_allowed.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

---

## Zadanie 11: Build z podpisanych tagów `v*`, `releases/`, tag `v0.1.0`, CI (rozstrzygnięcie 12)

**Files:**
- Create: `scripts/release-lib.mjs`, `scripts/release-sums.mjs`, `releases/allowed_signers`, `releases/0.1.0.sha256`
- Modify: `scripts/build.mjs` (całość), `.github/workflows/ci.yml`
- Test: `test/unit/build.test.js`

**Interfaces:**
- Consumes: `scripts/sums.mjs` (zadanie 1).
- Produces:
  - `scripts/release-lib.mjs`: `class BuildError`, `TAG_RE`, `releaseTags() → string[]` (posortowane semantycznie), `verifySignedTag(tag, signersFile)`, `assertInHistory(tag, ref = "HEAD")`, `versionAt(ref) → "X.Y.Z"`, `extractSrc(ref, dest)`, `sumsAt(ref) → Promise<string>`.
  - `node scripts/release-sums.mjs [<ref>=HEAD]` → na stdout zawartość `releases/<X.Y.Z>.sha256` (sumy `src/` z `git archive <ref>`).
  - `node scripts/build.mjs [<katalog>=dist]` → `dist/` = `public/` + `v<X.Y.Z>/` z każdego podpisanego tagu + `SHA256SUMS`; każdy błąd = `Błąd builda: …` na stderr i kod 1.
  - Reguły (wszystkie łamią build): brak tagów; tag nie `vX.Y.Z`; tag bez ważnego podpisu wg `releases/allowed_signers`; tag spoza historii `HEAD`; `VERSION` w tagu ≠ nazwa taga; brak albo niezgodny `releases/<X>.sha256`; `releases/<X>.sha256` bez taga dla wersji innej niż bieżąca; `src/` w `HEAD` różny od `releases/<VERSION>.sha256` (po wydaniu: „podbij VERSION"; przed: „nieaktualne").

- [ ] **Krok 1: Test, który ma paść**

`test/unit/build.test.js`:

```js
import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const SCRIPTS = ["build.mjs", "release-lib.mjs", "release-sums.mjs", "sums.mjs"];
const run = (cwd, cmd, args) => execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

// Tymczasowe repo z własnym kluczem SSH (bez kluczy użytkownika) i skryptami builda z tego repo.
function makeRepo() {
  const dir = mkdtempSync(join(tmpdir(), "sejf-build-"));
  run(dir, "ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", join(dir, ".key")]);
  const git = (...args) => run(dir, "git", args);
  git("init", "-q", "-b", "main");
  for (const [key, value] of [
    ["user.name", "Test"],
    ["user.email", "test@example.com"],
    ["commit.gpgsign", "false"],
    ["tag.gpgsign", "false"],
    ["gpg.format", "ssh"],
    ["user.signingkey", join(dir, ".key")],
  ]) git("config", key, value);
  for (const d of ["scripts", "src", "public", "releases"]) mkdirSync(join(dir, d));
  for (const f of SCRIPTS) cpSync(join(ROOT, "scripts", f), join(dir, "scripts", f));
  writeFileSync(join(dir, ".gitignore"), ".key\n.key.pub\ndist/\n");
  writeFileSync(join(dir, "releases/allowed_signers"), `test@example.com namespaces="git" ${readFileSync(join(dir, ".key.pub"), "utf8").trim()}\n`);
  writeFileSync(join(dir, "public/revoked.json"), '{"revoked": []}\n');
  const repo = {
    dir,
    git,
    write(version, body = "a") {
      writeFileSync(join(dir, "src/config.js"), `export const VERSION = "${version}";\n`);
      writeFileSync(join(dir, "src/a.js"), `export const A = "${body}";\n`);
    },
    commit(message = "zmiana") {
      git("add", "-A");
      git("commit", "-q", "-m", message);
    },
    prepare(version) {
      writeFileSync(join(dir, `releases/${version}.sha256`), run(dir, "node", ["scripts/release-sums.mjs", "HEAD"]));
      repo.commit(`sumy ${version}`);
    },
    signTag(version) {
      git("tag", "-s", `v${version}`, "-m", `v${version}`);
    },
    release(version, body) {
      repo.write(version, body);
      repo.commit();
      repo.prepare(version);
      repo.signTag(version);
    },
    build() {
      return run(dir, "node", ["scripts/build.mjs", "dist"]);
    },
    buildError() {
      try {
        repo.build();
      } catch (e) {
        return e.stderr;
      }
      throw new Error("build miał paść");
    },
  };
  return repo;
}

const read = (r, path) => readFileSync(join(r.dir, path), "utf8");

describe("build z podpisanych tagów (rozstrzygnięcie 12, Review Focus 5)", { timeout: 60_000 }, () => {
  it("podpisany tag + sumy -> dist/v<X>/ i SHA256SUMS", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.build();
    expect(read(r, "dist/v1.0.0/a.js")).toBe('export const A = "a";\n');
    expect(read(r, "dist/SHA256SUMS")).toContain("  v1.0.0/a.js\n");
    expect(read(r, "dist/SHA256SUMS")).toContain("  revoked.json\n");
  });

  it("dwa buildy dają te same sumy (odtwarzalność)", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.build();
    const first = read(r, "dist/SHA256SUMS");
    r.build();
    expect(read(r, "dist/SHA256SUMS")).toBe(first);
  });

  it("wydane wersje żyją równolegle", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.release("1.1.0", "b");
    r.build();
    expect(read(r, "dist/v1.0.0/a.js")).toContain('"a"');
    expect(read(r, "dist/v1.1.0/a.js")).toContain('"b"');
  });

  it("przygotowany release (sumy bez taga) bieżącej wersji -> ok, jeszcze niepublikowany", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.write("1.1.0", "b");
    r.commit();
    r.prepare("1.1.0");
    r.build();
    expect(existsSync(join(r.dir, "dist/v1.0.0"))).toBe(true);
    expect(existsSync(join(r.dir, "dist/v1.1.0"))).toBe(false);
  });

  it("brak tagów -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    expect(r.buildError()).toContain("brak tagów v*");
  });

  it("tag w złym formacie -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.git("tag", "-s", "v1.0", "-m", "v1.0");
    expect(r.buildError()).toContain("tag v1.0: oczekiwano vX.Y.Z");
  });

  it("tag bez podpisu -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    r.prepare("1.0.0");
    r.git("tag", "-a", "v1.0.0", "-m", "v1.0.0");
    expect(r.buildError()).toContain("v1.0.0: brak ważnego podpisu");
  });

  it("tag spoza historii HEAD -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.git("checkout", "-q", "-b", "boczna");
    r.release("1.0.1", "x");
    r.git("checkout", "-q", "main");
    expect(r.buildError()).toContain("v1.0.1: tag spoza historii HEAD");
  });

  it("tag bez pliku sum -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    r.signTag("1.0.0");
    expect(r.buildError()).toContain("v1.0.0: brak releases/1.0.0.sha256");
  });

  it("sumy niezgodne z treścią taga -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    writeFileSync(join(r.dir, "releases/1.0.0.sha256"), `${"0".repeat(64)}  a.js\n`);
    r.commit("złe sumy");
    r.signTag("1.0.0");
    expect(r.buildError()).toContain("v1.0.0: treść różni się od releases/1.0.0.sha256");
  });

  it("zmiana src/ wydanej wersji bez podbicia VERSION -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.write("1.0.0", "zmienione");
    r.commit();
    expect(r.buildError()).toContain("src/ zmieniony po wydaniu v1.0.0");
  });

  it("nieaktualne sumy przygotowanego release'u -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.write("1.1.0", "b");
    r.commit();
    r.prepare("1.1.0");
    r.write("1.1.0", "c");
    r.commit();
    expect(r.buildError()).toContain("releases/1.1.0.sha256 nieaktualne");
  });

  it("sumy bez taga dla wersji innej niż bieżąca -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "releases/0.9.0.sha256"), "x\n");
    r.commit();
    expect(r.buildError()).toContain("releases/0.9.0.sha256 bez tagu v0.9.0");
  });
});
```

Run: `npx vitest run test/unit/build.test.js`
Expected: FAIL (`scripts/release-sums.mjs` / `release-lib.mjs` nie istnieją — `cpSync` rzuca `ENOENT`).

- [ ] **Krok 2: `scripts/release-lib.mjs` i `scripts/release-sums.mjs`**

`scripts/release-lib.mjs`:

```js
// Wspólne dla build.mjs i release-sums.mjs: tagi wydań, podpisy SSH, treść src/ prosto z gita.
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { sumsOf } from "./sums.mjs";

export class BuildError extends Error {}

export const TAG_RE = /^v(\d+)\.(\d+)\.(\d+)$/;

const git = (args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"], maxBuffer: 1 << 28 });

// Kod wyjścia gita. execFileSync rzuca błąd z liczbowym `status`, gdy proces skończył się kodem ≠ 0 —
// tylko ten przypadek zamieniamy na kod; brak gita (ENOENT, bez `status`) leci dalej.
function gitStatus(args) {
  try {
    git(args);
    return 0;
  } catch (e) {
    if (typeof e.status === "number") return e.status;
    throw e;
  }
}

export function releaseTags() {
  const tags = git(["tag", "--list", "v*"]).split("\n").filter(Boolean);
  for (const tag of tags) {
    if (!TAG_RE.test(tag)) throw new BuildError(`tag ${tag}: oczekiwano vX.Y.Z`);
  }
  const parts = (tag) => tag.match(TAG_RE).slice(1).map(Number);
  return tags.sort((a, b) => {
    const [x, y] = [parts(a), parts(b)];
    return x[0] - y[0] || x[1] - y[1] || x[2] - y[2];
  });
}

export function verifySignedTag(tag, signersFile) {
  const status = gitStatus(["-c", `gpg.ssh.allowedSignersFile=${resolve(signersFile)}`, "verify-tag", tag]);
  if (status !== 0) throw new BuildError(`${tag}: brak ważnego podpisu (${signersFile})`);
}

export function assertInHistory(tag, ref = "HEAD") {
  const status = gitStatus(["merge-base", "--is-ancestor", tag, ref]);
  if (status === 1) throw new BuildError(`${tag}: tag spoza historii ${ref}`);
  if (status !== 0) throw new BuildError(`${tag}: git merge-base zakończył się kodem ${status}`);
}

export function versionAt(ref) {
  const match = git(["show", `${ref}:src/config.js`]).match(/export const VERSION = "(\d+\.\d+\.\d+)";/);
  if (!match) throw new BuildError(`${ref}: brak VERSION w src/config.js`);
  return match[1];
}

export function extractSrc(ref, dest) {
  mkdirSync(dest, { recursive: true });
  const tar = execFileSync("git", ["archive", "--format=tar", ref, "src"], { maxBuffer: 1 << 28 });
  execFileSync("tar", ["-x", "--strip-components=1", "-C", dest], { input: tar });
}

export async function sumsAt(ref) {
  const tmp = mkdtempSync(join(tmpdir(), "sejf-src-"));
  try {
    extractSrc(ref, tmp);
    return await sumsOf(tmp);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
}
```

`scripts/release-sums.mjs`:

```js
// Sumy src/ z `git archive <ref>` w formacie releases/<X.Y.Z>.sha256.
// Użycie: node scripts/release-sums.mjs [<ref>=HEAD] > releases/<X.Y.Z>.sha256
import { sumsAt } from "./release-lib.mjs";

process.stdout.write(await sumsAt(process.argv[2] ?? "HEAD"));
```

- [ ] **Krok 3: `scripts/build.mjs`**

Zastąp cały plik:

```js
// Składa publikowane drzewo (rozstrzygnięcie 12): dist/ = public/ + v<X.Y.Z>/ z KAŻDEGO podpisanego
// tagu vX.Y.Z (`git archive <tag> src`), plus dist/SHA256SUMS. Wydane wersje są niezmienne i żyją
// równolegle; wycofuje się je wpisem w public/revoked.json, nie usunięciem.
// Użycie: node scripts/build.mjs [katalog=dist]
import { existsSync } from "node:fs";
import { cp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { assertInHistory, BuildError, extractSrc, releaseTags, sumsAt, verifySignedTag, versionAt } from "./release-lib.mjs";
import { sumsOf } from "./sums.mjs";

const SIGNERS = "releases/allowed_signers";
const out = process.argv[2] ?? "dist";

try {
  await build(out);
} catch (e) {
  // BuildError = naruszona reguła wydań (komunikat dla człowieka); każdy inny wyjątek to błąd skryptu.
  if (!(e instanceof BuildError)) throw e;
  console.error(`Błąd builda: ${e.message}`);
  process.exit(1);
}

async function build(target) {
  const tags = releaseTags();
  if (tags.length === 0) throw new BuildError("brak tagów v* — dist/ bez wydanych wersji zdjąłby je z Pages");
  const current = versionAt("HEAD");
  const prepared = (await readdir("releases")).filter((f) => f.endsWith(".sha256")).map((f) => f.slice(0, -".sha256".length));
  for (const version of prepared) {
    if (!tags.includes(`v${version}`) && version !== current) {
      throw new BuildError(`releases/${version}.sha256 bez tagu v${version} (dozwolone tylko dla bieżącej wersji ${current})`);
    }
  }

  await rm(target, { recursive: true, force: true });
  await cp("public", target, { recursive: true });
  for (const tag of tags) {
    const version = tag.slice(1);
    verifySignedTag(tag, SIGNERS);
    assertInHistory(tag);
    const tagged = versionAt(tag);
    if (tagged !== version) throw new BuildError(`${tag}: src/config.js ma VERSION ${tagged}`);
    const sumsFile = `releases/${version}.sha256`;
    if (!existsSync(sumsFile)) throw new BuildError(`${tag}: brak ${sumsFile}`);
    const dest = join(target, `v${version}`);
    extractSrc(tag, dest);
    if ((await sumsOf(dest)) !== (await readFile(sumsFile, "utf8"))) throw new BuildError(`${tag}: treść różni się od ${sumsFile}`);
  }

  if (prepared.includes(current) && (await sumsAt("HEAD")) !== (await readFile(`releases/${current}.sha256`, "utf8"))) {
    throw new BuildError(
      tags.includes(`v${current}`)
        ? `src/ zmieniony po wydaniu v${current} — podbij VERSION w src/config.js`
        : `releases/${current}.sha256 nieaktualne wobec src/ (node scripts/release-sums.mjs HEAD)`,
    );
  }

  await writeFile(join(target, "SHA256SUMS"), await sumsOf(target, { exclude: ["SHA256SUMS"] }));
  console.log(`dist: ${tags.join(", ")}`);
}
```

Run: `npx vitest run test/unit/build.test.js`
Expected: PASS (13 testów).

- [ ] **Krok 4: Plik podpisujących i tag `v0.1.0`**

Klucz podpisujący użytkownika (ten sam, którym repo podpisuje commity; `gpg.format=ssh`, `tag.gpgsign=true` — sprawdzone 2026-10-25):

```bash
cp /Volumes/SSD/Programowanie/bobik-sejf/.git/allowed_signers releases/allowed_signers
cat releases/allowed_signers
cut -d' ' -f1,2 ~/.ssh/id_ed25519.pub
```

Expected: linia `michal.dtz@gmail.com namespaces="git" ssh-ed25519 AAAA…`, a klucz (`ssh-ed25519 AAAA…`) identyczny z wynikiem `cut`.

Tag `v0.1.0` na ostatnim zielonym deployu `main` (`f690d3a`, decyzja planu P11):

```bash
git tag -s v0.1.0 f690d3ad47582beba8d0b470c00d24ab46d7f0fb -m "bobik-sejf v0.1.0 — szkielet i demo kluczy sprzętowych (unieważniona w v0.2.0)"
git -c gpg.ssh.allowedSignersFile="$PWD/releases/allowed_signers" verify-tag v0.1.0
node scripts/release-sums.mjs v0.1.0 > releases/0.1.0.sha256
cat releases/0.1.0.sha256
```

Expected: `Good "git" signature for michal.dtz@gmail.com …`; 14 linii sum (pliki `src/` z v0.1.0, m.in. `demo.html`, `vault.js`, `webauthn.js`).

Porównanie z tym, co dziś serwuje Pages (wydana treść nie może się zmienić):

```bash
# zmienna `p`, nie `path`: w zsh `path` jest powiązane z $PATH i pętla gubi curl/shasum/cut
while read -r sum p; do
  live=$(curl -fsS "https://bobik-2.github.io/v0.1.0/$p" | shasum -a 256 | cut -d' ' -f1)
  [ "$live" = "$sum" ] && echo "OK  $p" || echo "RÓŻNICA  $p"
done < releases/0.1.0.sha256
```

Expected: same `OK`. Jakakolwiek `RÓŻNICA` = opublikowana treść ≠ `f690d3a`; zatrzymaj się i zgłoś (nie zakładaj taga na innym commicie bez zgody).

Lokalny build:

```bash
node scripts/build.mjs dist && ls dist && head -3 dist/SHA256SUMS
```

Expected: `dist: v0.1.0`; w `dist/` są `index.html`, `revoked.json`, `v0.1.0/`, `SHA256SUMS` (bieżąca 0.2.0 nie jest jeszcze wydana — brak `releases/0.2.0.sha256`).

- [ ] **Krok 5: CI — pełna historia z tagami, ręczny deploy**

`.github/workflows/ci.yml` (cały plik; SHA akcji bez zmian):

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
  # Ponowny deploy z main (np. po wypchnięciu taga, gdy merge już się opublikował).
  workflow_dispatch:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
          # Build składa dist/ z podpisanych tagów v* (rozstrzygnięcie 12): potrzebna cała historia.
          fetch-depth: 0
          fetch-tags: true
      - uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0
        with:
          node-version: 24
          cache: npm
      - run: npm ci
      - name: Vitest
        run: npx vitest run
      - name: Przeglądarki Playwright
        run: npx playwright install --with-deps chromium firefox webkit
      - name: Playwright
        run: npx playwright test
      - name: Wydane wersje i odtwarzalność (podpisy tagów, releases/*.sha256)
        run: |
          node scripts/build.mjs /tmp/build-a
          node scripts/build.mjs /tmp/build-b
          diff /tmp/build-a/SHA256SUMS /tmp/build-b/SHA256SUMS
          cat /tmp/build-a/SHA256SUMS
      - name: Build do publikacji
        if: github.ref == 'refs/heads/main' && github.event_name != 'pull_request'
        run: node scripts/build.mjs dist
      - uses: actions/configure-pages@45bfe0192ca1faeb007ade9deae92b16b8254a0d # v6.0.0
        if: github.ref == 'refs/heads/main' && github.event_name != 'pull_request'
      - uses: actions/upload-pages-artifact@fc324d3547104276b827a68afc52ff2a11cc49c9 # v5.0.0
        if: github.ref == 'refs/heads/main' && github.event_name != 'pull_request'
        with:
          path: dist

  # Publikacja na https://bobik-2.github.io — tylko z main (polityka środowiska github-pages), po zielonym `test`.
  deploy:
    needs: test
    if: github.ref == 'refs/heads/main' && github.event_name != 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      pages: write
      id-token: write
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    concurrency:
      group: pages
      cancel-in-progress: false
    steps:
      - id: deployment
        uses: actions/deploy-pages@368f82528645a54fb793d4d04e342629a3f51346 # v5.0.1
```

- [ ] **Krok 6: Pełne testy i commit**

Run: `npx vitest run`
Expected: PASS.

```bash
git add scripts/release-lib.mjs scripts/release-sums.mjs scripts/build.mjs releases/allowed_signers releases/0.1.0.sha256 .github/workflows/ci.yml test/unit/build.test.js
git commit -m "build: dist/ z podpisanych tagów v*, releases/<X.Y.Z>.sha256, tag v0.1.0

Rozstrzygnięcie 12: wydane wersje niezmienne i równoległe. Build pada przy
braku tagów, tagu bez podpisu (releases/allowed_signers), tagu spoza historii,
niezgodnych sumach i zmianie src/ wydanej wersji bez podbicia VERSION.
v0.1.0 = f690d3a, sumy zgodne z opublikowanymi plikami. CI pobiera całą
historię z tagami; workflow_dispatch do ponownego deployu z main.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
```

- [ ] **Krok 7: [zgoda użytkownika] Wypchnięcie taga `v0.1.0`**

Musi nastąpić przed pierwszym wypchnięciem gałęzi (zadanie 12): CI na PR-ze buduje z tagów, a bez `v0.1.0` build pada („brak tagów v*").

```bash
git push origin v0.1.0
git ls-remote --tags origin v0.1.0
```

Expected: `refs/tags/v0.1.0` na zdalnym repo.

---

## Zadanie 12: Release v0.2.0 — unieważnienie 0.1.0, README, PR, podpisany tag, deploy

**Files:**
- Modify: `package.json`, `package-lock.json` (wersja 0.2.0), `public/revoked.json`, `public/index.html`, `README.md`
- Create: `releases/0.2.0.sha256`
- Test: `test/unit/release.test.js`

**Interfaces:**
- Consumes: build i `release-sums.mjs` (zadanie 11), cały `src/` (zadania 1–10, zamrożony).
- Produces: release `v0.2.0` pod `https://bobik-2.github.io/v0.2.0/` (zgodny z `KEYVAULT_VAULT_VERSION="0.2.0"` w bobik-2), `0.1.0` w `revoked.json`, `test/vectors/sejf_v1.json` dla S-1 w B2.

- [ ] **Krok 1: Test, który ma paść**

`test/unit/release.test.js`:

```js
import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { VERSION } from "../../src/config.js";

const read = (path) => readFileSync(new URL(`../../${path}`, import.meta.url), "utf8");

it("0.1.0 (demo, origin E2E w konfiguracji) jest unieważniona, bieżąca wersja nie", () => {
  const { revoked } = JSON.parse(read("public/revoked.json"));
  expect(revoked).toContain("0.1.0");
  expect(revoked).not.toContain(VERSION);
});

it("package.json i src/config.js mają tę samą wersję", () => {
  expect(JSON.parse(read("package.json")).version).toBe(VERSION);
  expect(JSON.parse(read("package-lock.json")).version).toBe(VERSION);
});

it("strona główna originu wskazuje bieżącą wersję demo", () => {
  expect(read("public/index.html")).toContain(`href="v${VERSION}/demo.html"`);
});

it("README: jedyne odłożenie — hosty produkcyjne panelu (P12)", () => {
  expect(read("README.md")).toContain("TODO przed użyciem produkcyjnym");
});
```

Run: `npx vitest run test/unit/release.test.js`
Expected: FAIL (lista unieważnień pusta, `package.json` ma 0.1.0).

- [ ] **Krok 2: Wersja, unieważnienie, strona główna**

```bash
npm version 0.2.0 --no-git-tag-version
```

`public/revoked.json`:

```json
{"revoked": ["0.1.0"]}
```

`public/index.html` (cały plik):

```html
<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sejf kluczy bobik</title>
</head>
<body>
<h1>Sejf kluczy bobik</h1>
<p>Ten origin hostuje sejf kluczy osadzany w panelu bobik-2.</p>
<ul>
  <li><a href="v0.2.0/demo.html">Demo i diagnostyka kluczy sprzętowych (v0.2.0)</a></li>
  <li>v0.1.0 — unieważniona (<a href="revoked.json">revoked.json</a>)</li>
</ul>
</body>
</html>
```

- [ ] **Krok 3: README**

Zastąp cały `README.md` poniższym. Wartości `ancestorOrigins` z logu testu w zadaniu 9 są już wpisane (Chromium/WebKit `["http://127.0.0.1:8000"]`, Firefox `["null"]`; E2E ich wymaga).

````markdown
# bobik-sejf

Sejf kluczy dla [bobik-2](https://github.com/iplweb/bobik-2): mała statyczna strona osadzana w
panelu lekarza jako iframe na **osobnym originie** (`https://bobik-2.github.io`, RP ID WebAuthn
`bobik-2.github.io` — na zawsze). Trzyma klucz prywatny lekarza, klucze prywatne klinik i DEK
otwartych wywiadów wyłącznie jako nieeksportowalne `CryptoKey` w pamięci; odblokowanie kluczem
sprzętowym z PIN-em (WebAuthn PRF, `userVerification: "required"`). Z panelem rozmawia wyłącznie
przez `postMessage`; z serwerem bobik-2 — wcale.

Kontrakt (formaty F1–F8, protokół, limity, kody błędów): spec B w repo bobik-2,
`docs/superpowers/specs/2026-10-24-szyfrowanie-b-sejf-design.md`. Plan tej wersji:
`docs/plans/2026-10-25-b1-protokol-krypto.md`.

## TODO przed użyciem produkcyjnym

`ALLOWED_PARENT_ORIGINS` w `src/config.js` zawiera dziś wyłącznie origin atrapy panelu E2E
(`http://127.0.0.1:8000`) — hosty produkcyjne panelu bobik-2 nie są ustalone (spec B, „Nie
ustalono"). Przed pierwszym użyciem klinicznym dopisz je (każda klinika ma własne `Site.domain`)
i wydaj nową wersję. To jedyne odłożenie w v0.2.0; do tego czasu w bobik-2 obowiązuje
`KEYVAULT_BROWSER_CLINICS_ENABLED=False`.

## Układ

- `src/` — kod jednej wersji sejfu, publikowany pod `/v<VERSION>/`: rdzeń `core.js` (stany
  `refusing`/`locked`/`unlocked`, `busy`, blokada), operacje `ops/`, kryptografia `crypto/`,
  limit `limits.js`, UI `ui.js` + `index.html`, spięcie z przeglądarką `vault.js`, demo `demo.html`.
- `src/vendor/` — `@hpke/core` 1.9.0 i `@hpke/common` 1.10.1 z `node_modules`, importy przepisane
  na ścieżki względne (CSP `script-src 'self'` nie dopuszcza import map). Regeneracja:
  `npm run vendor`; sumy w `src/vendor/SHA256SUMS`, test porównuje je z `node_modules`.
- `public/` — korzeń originu (`index.html`, `revoked.json`).
- `releases/` — `allowed_signers` (klucze podpisujące tagi) i `<X.Y.Z>.sha256` każdej wersji.
- `scripts/` — `build.mjs`, `release-sums.mjs`, `serve.mjs`, `gen-vectors.mjs`, `vendor-hpke.mjs`.
- `test/unit/` — Vitest; `test/e2e/` — Playwright z atrapą panelu; `test/vectors/` — wektory krzyżowe.

## Wersje i release

`dist/` powstaje wyłącznie z **podpisanych tagów `vX.Y.Z`** (`git archive <tag> src` →
`dist/v<X.Y.Z>/`), nigdy z bieżącego `src/`. Wydane wersje są niezmienne i żyją równolegle;
wycofuje się je wpisem w `public/revoked.json` (sejf w unieważnionej wersji odpowiada tylko na
`hello`), nie usunięciem. Build pada, gdy: nie ma tagów, tag nie ma ważnego podpisu wg
`releases/allowed_signers`, tag nie leży w historii `HEAD`, sumy nie zgadzają się z
`releases/<X.Y.Z>.sha256`, albo `src/` wydanej wersji zmieniono bez podbicia `VERSION`.

Nowa wersja:

1. Podbij `VERSION` w `src/config.js` i `npm version X.Y.Z --no-git-tag-version`.
2. Gdy `src/` jest gotowe i zacommitowane: `node scripts/release-sums.mjs HEAD > releases/X.Y.Z.sha256`, commit.
3. PR → zielone CI → podpisany tag na głowie PR-a: `git tag -s vX.Y.Z -m "…"`, `git push origin vX.Y.Z`.
4. Merge **commitem scalającym** (nie squash — tag musi zostać w historii `main`). Deploy z `main`
   publikuje wszystkie wersje. Ponowny deploy: `gh workflow run CI --ref main`.
5. W bobik-2: commit zmieniający domyślne `KEYVAULT_VAULT_VERSION` w `settings.py`.

## Dev i E2E

```bash
npm ci
npx vitest run
npx playwright test      # panel 127.0.0.1:8000, obcy panel 127.0.0.1:8002, sejf localhost:8001
```

`node scripts/serve.mjs <port> <host> <prefiks>=<katalog>… --dev-config` podmienia przy serwowaniu
listę originów panelu w `src/config.js` na `http://127.0.0.1:8000` (atrapa) i
`http://localhost:8000` (dev bobik-2); `--parent-origins=a,b` podaje własną listę (np. port
`live_server` w E2E bobik-2). Przykład dla dev bobik-2 (`KEYVAULT_VAULT_ORIGIN=http://localhost:8001`):

```bash
node scripts/serve.mjs 8001 localhost /=public /v0.2.0=src --dev-config
```

Podmiana nigdy nie trafia do `dist/`.

Zaobserwowane w Chromium (iframe z `referrerpolicy="no-referrer"`, jak w B2):
`location.ancestorOrigins` = `["http://127.0.0.1:8000"]` w Chromium i WebKit, `["null"]` w Firefoksie
(maskowanie przez `no-referrer`). Filtr wymaga dokładnie jednego przodka, równego `event.origin` albo
`"null"`; dozwolony panel osadzony w obcej stronie daje dwa wpisy i nie dostaje odpowiedzi (test E2E
we wszystkich trzech silnikach). Bez `ancestorOrigins` (starsze przeglądarki) rozstrzyga `event.origin`.

## Dla panelu (B3)

- `hello` zaraz po załadowaniu, porównanie `version`; brak odpowiedzi w 5 s = host spoza listy.
- `open`: element `sealed` wymaga `interview_id` (dokleja go panel z `ciphertexts.interview`), pola
  z `blob: null` panel pomija; nowe wywiady w paczkach ≤ 10 (limit okna 5 min).
- `unlock` przyjmuje `credentials` z `GET state/` wprost (nadmiarowe pola ignorowane).
- Operacje interaktywne: limit 120 s po stronie panelu i sejfu; druga naraz → `busy`.
- Zdarzenie `{v: 1, event: "locked", reason}` przychodzi przy każdej blokadzie ze stanu `unlocked`
  (`user`, `idle`, `max_age`, `limit`). Progi `idle`/`max_age` sejf sprawdza też przy każdym żądaniu:
  żądanie po terminie dostaje `locked` (i zdarzenie), nawet gdy zdławiony timer jeszcze nie zadziałał.
- Ponowny `unlock` w stanie `unlocked` podmienia sesję i zeruje liczniki **bez** zdarzenia `locked`:
  załadowane klucze kliniki i DEK znikają, panel musi ponownie wysłać `load_clinic_key` (inaczej
  dostanie `clinic_key_not_loaded`).
- Potwierdzenia w sejfie: fokus na „Anuluj”, przycisk zatwierdzenia nieaktywny przez 1 s po
  pokazaniu (ochrona przed clickjackingiem) — panel nie powinien zakładać natychmiastowego zatwierdzenia.
- Etykiety (`display_name`, `clinic_label`, `recipient_label`) maks. 80 znaków, `study_code` maks. 64;
  dozwolone tylko widoczne znaki w NFC z pojedynczą zwykłą spacją (bez znaków sterujących,
  formatujących, separatorów wierszy, spacji innych niż U+0020, podwójnych spacji i spacji na
  brzegach) — inaczej `bad_args`. Pola modeli bobik-2 mają do 200 znaków, więc panel normalizuje
  i skraca etykietę przed wysłaniem.
- `grant_lease`: `clinic_wrap` ma dokładnie 113 B, inna długość → `bad_args` przed pytaniem lekarza.
- Potwierdzenia pokazują identyfikatory związane kryptograficznie: numer kliniki, numer lekarza
  odbiorcy, UUID wywiadu (`interview_id`) — przed etykietami z panelu.
- Iframe sejfu musi siedzieć **bezpośrednio** w dokumencie panelu najwyższego poziomu: żadnych
  zagnieżdżeń (panel w ramce, także własnej), sandboxu bez `allow-same-origin`, `data:`/`srcdoc`.
  Więcej niż jeden przodek w `location.ancestorOrigins` = brak odpowiedzi. `referrerpolicy="no-referrer"`
  na samym iframe'ie (jak w B2) jest dozwolone (Firefox maskuje wtedy rodzica do `"null"`, sejf to przyjmuje).
  Nagłówek `frame-ancestors` stron panelu (B2) zostaje potrzebny dla przeglądarek bez `ancestorOrigins`.

## Wektory krzyżowe

- `test/vectors/bobik2_v1.json` — kopia z bobik-2 (`src/bobik2/crypto/tests/vectors/`), suma w
  `test/vectors/SHA256SUMS` zgodna z bobik-2.
- `test/vectors/sejf_v1.json` — formaty sejfu (F1–F4, F6, F7) z podstawionym wynikiem PRF;
  generator `node scripts/gen-vectors.mjs` uruchamiany **wyłącznie** przy zmianie formatu (wynik
  jest losowy, a kopia żyje w bobik-2 i trzeba ją przenieść tym samym commitem formatu).

## Testy ręczne (sprzęt)

YubiKey 5 na Windows w Chrome, Edge i Firefox, w cross-origin iframe: rejestracja z PIN-em (klucz
z firmware ≥ 5.8 — jedno dotknięcie; 5.2–5.7 — drugie dotknięcie), odblokowanie jednym z dwóch
kluczy, blokada Safari. Wynik Firefoksa rozstrzyga, czy rejestracja zostaje w iframe'ie (spec B,
rozstrzygnięcie 15).

## Hosting

Organizacja GitHub **`bobik-2`** (osobna od `iplweb`), repo `bobik-2.github.io`. W tej organizacji
**nie może** być żadnych innych stron Pages — dzieliłyby origin z sejfem. Wymuszone 2FA na
kluczach sprzętowych, minimum właścicieli, chroniona `main` z wymaganym zielonym CI i podpisanymi
commitami, podpisane tagi; deploy tylko z `main` (polityka środowiska `github-pages`).
````

- [ ] **Krok 4: Pełne testy**

Sprawdź obciążenie (Global Constraints), potem:

Run: `npx vitest run && npx playwright test`
Expected: PASS we wszystkich projektach.

- [ ] **Krok 5: Sumy wydania i commit release'u**

`src/` jest już zamrożone (ten krok go nie zmienia). Sumy liczone z `HEAD`, więc najpierw commit zmian z kroków 2–3:

```bash
git add package.json package-lock.json public/revoked.json public/index.html README.md test/unit/release.test.js
git commit -m "release: v0.2.0 — unieważnienie 0.1.0, README (wersje z tagów, dev, wektory)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
node scripts/release-sums.mjs HEAD > releases/0.2.0.sha256
git add releases/0.2.0.sha256
git commit -m "release: sumy v0.2.0 (releases/0.2.0.sha256)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
Claude-Session: https://claude.ai/code/session_011119mgvjred5vK74v8cQfk"
node scripts/build.mjs dist && ls dist
```

Expected: `dist: v0.1.0` (0.2.0 przygotowana, jeszcze bez taga — build przechodzi, bo sumy zgadzają się z `src/`).

- [ ] **Krok 6: [zgoda użytkownika] Gałąź i PR**

```bash
git push -u origin feat/b1-protokol-krypto
gh pr create --base main --title "B1: protokół i kryptografia sejfu (v0.2.0)" --body "$(cat <<'EOF'
Plan: docs/plans/2026-10-25-b1-protokol-krypto.md (spec B w bobik-2, wiersz B1).

- operacje hello, register, unlock, add_credential, load_clinic_key, create_clinic_key, grant_clinic_access, open, grant_lease, lock; stany refusing/locked/unlocked, busy, limit odszyfrowań, zdarzenie locked
- kryptografia F1–F7 zgodna z bobik-2 (wektory bobik2_v1.json), wektory sejf_v1.json dla S-1 w B2
- @hpke/core 1.9.0 wendorowane bez bundlera, userVerification required
- build z podpisanych tagów v*, releases/<X.Y.Z>.sha256, v0.1.0 unieważniona
- odstępstwo P12: ALLOWED_PARENT_ORIGINS bez hostów produkcyjnych (TODO w README)

Testy: Vitest V-1…V-8, Playwright P-1…P-5.

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_011119mgvjred5vK74v8cQfk
EOF
)"
gh pr checks --watch
```

Expected: job `test` zielony (Vitest, Playwright w trzech przeglądarkach, build z tagami).

- [ ] **Krok 7: [zgoda użytkownika] Podpisany tag `v0.2.0` na głowie PR-a i merge**

Po przeglądzie PR-a przez użytkownika:

```bash
git status --short            # pusto
git tag -s v0.2.0 -m "bobik-sejf v0.2.0 — protokół i kryptografia sejfu (B1)"
git -c gpg.ssh.allowedSignersFile="$PWD/releases/allowed_signers" verify-tag v0.2.0
node scripts/build.mjs dist && ls dist
git push origin v0.2.0
gh pr merge --merge
gh run watch "$(gh run list --branch main --limit 1 --json databaseId --jq '.[0].databaseId')"
```

Expected: `Good "git" signature`; lokalny build: `dist: v0.1.0, v0.2.0`; merge commitem scalającym; job `deploy` na `main` zielony.

- [ ] **Krok 8: Weryfikacja publikacji**

```bash
curl -fsS https://bobik-2.github.io/revoked.json
# zmienna `p`, nie `path`: w zsh `path` jest powiązane z $PATH i pętla gubi curl/shasum/cut
while read -r sum p; do
  live=$(curl -fsS "https://bobik-2.github.io/v0.2.0/$p" | shasum -a 256 | cut -d' ' -f1)
  [ "$live" = "$sum" ] && echo "OK  $p" || echo "RÓŻNICA  $p"
done < releases/0.2.0.sha256
curl -fsS -o /dev/null -w "%{http_code}\n" https://bobik-2.github.io/v0.1.0/index.html
```

Expected: `{"revoked": ["0.1.0"]}`; same `OK` dla v0.2.0; `200` dla v0.1.0 (wersja zostaje opublikowana, tylko unieważniona). Jeśli Pages serwuje jeszcze starą treść (cache CDN), powtórz po kilku minutach.

- [ ] **Krok 9: Przekazanie do B2 i B3**

Bez zmian w kodzie — informacja dla osoby prowadzącej bobik-2:
- S-1 (B2, zadanie 10, część B): `cp /Volumes/SSD/Programowanie/bobik-sejf-feat-b1/test/vectors/sejf_v1.json <worktree bobik-2>/src/bobik2/crypto/tests/vectors/` w tagu `v0.2.0`; plik ma klucze z kontraktu B2 plus `prf_output` i `note`.
- B3: `KEYVAULT_VAULT_VERSION="0.2.0"` (już w `settings.py`), E2E klonuje sejf z tagu `v0.2.0` i serwuje `node scripts/serve.mjs 8001 localhost /=public /v0.2.0=src --parent-origins=http://localhost:<port live_server>`; uwagi dla panelu w README („Dla panelu (B3)").

---

## Pokrycie specu (samosprawdzenie)

| Wymaganie (spec B / ruling) | Zadanie |
|---|---|
| Wendorowanie `@hpke/core` 1.9.0 + `@hpke/common`, importy względne, sumy | 1 |
| F1–F3 (sól PRF, KEK, wrap lekarza), F4 (grant), F5 (DEK, Sealed, STC), F6 (RSA-OAEP-3072), F7 (odcisk), F8 (base64url) | 3, 3, 2, 4, 2 (test zgodności z bobik-2), 5 |
| `userVerification: "required"` (rozstrzygnięcie 6), PRF przy `create()` albo drugie dotknięcie (16) | 5, 7 |
| Operacje z tabeli, stany `refusing`/`locked`/`unlocked`, `busy`, `bad_args`, `unknown_op` | 7, 8 |
| Limit (rozstrzygnięcie 1), zegar wstrzykiwany, zdarzenie `locked` | 6, 8 |
| Filtr rodzica (rozstrzygnięcie 9), strona najwyższego poziomu | 9 |
| UI po polsku: przyciski, potwierdzenia, licznik, ekrany blokady | 6, 9, 10 |
| Podmiana `config.js` w `serve.mjs` (rozstrzygnięcie 11) | 9 |
| Build z tagów, `releases/<X.Y.Z>.sha256`, CI porównuje (rozstrzygnięcie 12); podpisy — bez odstępstwa | 11 |
| Wektory: kopia `bobik2_v1.json` z sumą, `gen-vectors.mjs` → `sejf_v1.json` + `SHA256SUMS` | 2, 4 |
| V-1 … V-8 | V-1: 2, 4, 8 · V-2: 7, 8 · V-3: 9 · V-4: 7, 8 · V-5: 6, 8 · V-6: 2, 4, 7, 8 · V-7: 4 · V-8: 5, 7 |
| P-1 … P-5 | P-1, P-2: 10 · P-3: 10 (+ obcy origin w 9) · P-4, P-5: 9 |
| Release v0.2.0, `package.json` 0.2.0, `0.1.0` w `revoked.json` | 12 |
| `ALLOWED_PARENT_ORIGINS` produkcyjne bez zmian + TODO w README (ruling) | 9 (test), 12 (README) |
