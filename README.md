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

**Wydanie z hostami produkcyjnymi: w tym samym PR-ze dopisz `0.2.0` do `public/revoked.json`.**
Wydane wersje są niezmienne i żyją równolegle, a v0.2.0 na stałe uznaje za panel
`http://127.0.0.1:8000` — po wydaniu produkcyjnym dalej działałaby pod produkcyjnym RP ID dla
dowolnego procesu na tym porcie u lekarza (`runserver`, narzędzie deweloperskie, malware). Nowa
wersja ma wyłącznie originy `https://`. Pilnuje tego `test/unit/release.test.js`.

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

Uwagi operacyjne:

- **Merge wyłącznie commitem scalającym.** Ruleset `main` dopuszcza też squash i rebase — nie używaj
  ich: otagowany commit wypada z historii `main` i każdy kolejny deploy pada na „tag spoza historii
  HEAD”. Tag wypychaj **przed** merge'em (build `main` z linkiem do niewydanej wersji w
  `public/index.html` pada).
- **Tagi `v*` nie mają rulesetu** (usunięcie, nadpisanie, tworzenie przez kogokolwiek z prawem
  zapisu). Build to łapie fail-closed (brak podpisu, sumy bez taga), skutkiem jest zablokowany
  deploy, nie publikacja.
- **Rotacja klucza podpisującego — procedura do ustalenia.** Wpis w `releases/allowed_signers` nie
  ma `valid-before`/`valid-after`; usunięcie klucza unieważnia podpisy wszystkich wydanych tagów
  i build pada na pierwszym z nich. Kierunek: nowy klucz w `allowed_signers`, `valid-before` na
  starym, ponowne podpisanie istniejących wersji nowym kluczem pod tymi samymi nazwami (nowy obiekt
  taga na ten sam commit, sumy bez zmian).
- `public/` idzie do `dist/` z `git archive HEAD public` (nie z dysku): wyłącznie `index.html`
  (bez `<script`) i `revoked.json` (`{"revoked": ["X.Y.Z", …]}`); build pada też, gdy każda
  zbudowana wersja jest unieważniona. Artefakt Pages buduje osobny job `build` bez `npm ci`.

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
- `unlock` przyjmuje `credentials` z `GET state/` wprost (nadmiarowe pola ignorowane), najwyżej
  **10 poświadczeń** na lekarza (więcej → `bad_args`, lekarz nie odblokuje sejfu). Serwer musi
  ograniczyć `add_credential` do 10 (B3).
- Po odblokowaniu sejf pokazuje „Lekarz nr N · odcisk Twojego klucza: …” — numer i odcisk, które
  odbiorca grantu podaje nadającemu.
- Operacje interaktywne: limit 120 s po stronie panelu i sejfu; druga naraz → `busy`.
- Zdarzenie `{v: 1, event: "locked", reason}` przychodzi przy każdej blokadzie ze stanu `unlocked`
  (`user`, `idle`, `max_age`, `limit`). Progi `idle`/`max_age` sejf sprawdza też przy każdym żądaniu:
  żądanie po terminie dostaje `locked` (i zdarzenie), nawet gdy zdławiony timer jeszcze nie zadziałał.
  Operacja interaktywna, której termin minął w trakcie potwierdzenia, też kończy się `locked`, bez wyniku.
- Ponowny `unlock` w stanie `unlocked` podmienia sesję i zeruje liczniki **bez** zdarzenia `locked`:
  załadowane klucze kliniki i DEK znikają, panel musi ponownie wysłać `load_clinic_key` (inaczej
  dostanie `clinic_key_not_loaded`).
- Potwierdzenia w sejfie: fokus na „Anuluj”, przycisk zatwierdzenia nieaktywny przez 1 s po
  pokazaniu (ochrona przed clickjackingiem) — panel nie powinien zakładać natychmiastowego zatwierdzenia.
- Etykiety (`display_name`, `clinic_label`, `recipient_label`) maks. 80 znaków, `study_code` maks. 64;
  dozwolone tylko widoczne znaki w NFC z pojedynczą zwykłą spacją (bez znaków sterujących,
  formatujących, separatorów wierszy, spacji innych niż U+0020, podwójnych spacji, spacji na
  brzegach, znaków `Default_Ignorable_Code_Point` — m.in. wypełniaczy Hangul i selektorów wariantu
  emoji — oraz U+2800) — inaczej `bad_args`. Pola modeli bobik-2 mają do 200 znaków, więc panel normalizuje
  i skraca etykietę przed wysłaniem.
- `grant_lease`: `clinic_wrap` ma dokładnie 113 B, inna długość → `bad_args` przed pytaniem lekarza.
- Potwierdzenia pokazują identyfikatory związane kryptograficznie: numer kliniki, numer lekarza
  odbiorcy, UUID wywiadu (`interview_id`) — we własnych wierszach, przed etykietami z panelu
  (etykieta stoi w jednym wierszu bez zawijania i może zostać ucięta w wąskiej ramce).
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
