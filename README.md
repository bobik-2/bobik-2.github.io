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

## Hosty panelu

`ALLOWED_PARENT_ORIGINS` w `src/config.js` to od v0.3.0 wyłącznie `https://bobik.iplweb.pl`.
Sejf odpowiada tylko panelowi pod tym originem; panel pod innym hostem (np. domena kliniki) dostaje
`vault_unreachable`, dopóki nowa wersja nie dopisze tego hosta. Wersja z hostem produkcyjnym ma
wyłącznie originy `https://`, a wersje z loopbackiem (0.1.0, 0.2.0) są unieważnione — inaczej
dowolny proces na `127.0.0.1:8000` u lekarza rozmawiałby z sejfem pod produkcyjnym RP ID. Pilnuje
tego `test/unit/release.test.js`. Lokalnie listę podmienia `scripts/serve.mjs` (sekcja „Dev i E2E”).

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

### Nowa wersja

1. Gałąź z `main`. Podbij `VERSION` w `src/config.js` i `npm version X.Y.Z --no-git-tag-version`
   (testy pilnują zgodności `package.json`, `package-lock.json` i linku w `public/index.html`).
   Nowy host panelu: dopisz go do bloku `// <parent-origins>`.
2. Unieważnienie starszej wersji: dopisz ją do `public/revoked.json` w tym samym PR-ze.
3. `npx vitest run` i `npx playwright test`. Gdy `src/` jest gotowe i zacommitowane:
   `node scripts/release-sums.mjs HEAD > releases/X.Y.Z.sha256`, commit.
4. PR → zielone `test` i `build` → podpisany tag na głowie PR-a: `git tag -s vX.Y.Z -m "vX.Y.Z"`,
   `git verify-tag vX.Y.Z`, `git push origin vX.Y.Z` — **przed** merge'em (build `main` z linkiem
   do niewydanej wersji pada).
5. Merge **commitem scalającym** (`gh pr merge --merge`).
   Deploy z `main` publikuje wszystkie wersje. Ponowny deploy: `gh workflow run CI --ref main`.
6. Sprawdzenie: `curl -fsSI https://bobik-2.github.io/vX.Y.Z/` (200) i
   `curl -fsS https://bobik-2.github.io/revoked.json`.
7. W bobik-2: commit zmieniający domyślne `KEYVAULT_VAULT_VERSION` w `settings.py` (job CI
   `e2e-vault` klonuje sejf w tagu `v<wersja>`).

### Zabezpieczenia repo

Stan docelowy ustawia `bash scripts/repo-rules.sh` (idempotentny, `gh` jako administrator repo):

- ustawienia repo: wyłącznie merge commitem (squash i rebase wyłączone) — otagowany commit musi
  zostać w historii `main`, inaczej każdy kolejny deploy pada na „tag spoza historii HEAD”;
- ruleset `main`: PR, wymagane checki `test` i `build`, podpisane commity, bez usuwania i
  force-pusha;
- ruleset `tagi v*`: tworzenie, przesuwanie i usuwanie tagów wydań wyłącznie przez administratora
  repo, podpisane tagi.

Build i tak sprawdza tagi fail-closed (brak podpisu, sumy bez taga → zablokowany deploy, nie
publikacja). Po zmianie nazwy joba w `.github/workflows/ci.yml` popraw listę checków w skrypcie.

### Rotacja klucza podpisującego

`releases/allowed_signers` to format `ssh-keygen` (ALLOWED SIGNERS). `git verify-tag` sprawdza
`valid-after`/`valid-before` względem daty taga.

**Planowa wymiana** (stary klucz nieskompromitowany):

1. Nowy klucz SSH (najlepiej sprzętowy: `ssh-keygen -t ed25519-sk`), dodany w GitHubie jako
   *signing key*; `git config user.signingkey <nowy>.pub`.
2. W `releases/allowed_signers`: staremu wpisowi dopisz `valid-before="RRRRMMDD"` (dzień wymiany),
   nowy dodaj z `namespaces="git",valid-after="RRRRMMDD"`. PR, merge commitem.
3. Stare tagi zostają ważne (podpisane przed `valid-before`); nowe podpisujesz nowym kluczem.
   Kontrola: `node scripts/build.mjs` lokalnie.

**Kompromitacja klucza** (data taga da się sfałszować, więc `valid-before` nie wystarcza):

1. Usuń stary klucz z GitHuba i z `releases/allowed_signers`, dodaj nowy (jak wyżej, bez dat).
2. Przejrzyj `git tag -l 'v*'` i `git log` od podejrzanej daty; każdą nieuprawnioną wersję dopisz do
   `public/revoked.json`.
3. Podpisz ponownie każdy wydany tag nowym kluczem, na ten sam commit (sumy w
   `releases/*.sha256` się nie zmieniają):
   `git tag -f -s vX.Y.Z 'vX.Y.Z^{commit}' -m vX.Y.Z` i `git push -f origin vX.Y.Z` (wymaga
   bypassu admina w rulesecie tagów).
4. PR ze zmianą `allowed_signers` i `revoked.json`, merge, sprawdzenie deployu jak w kroku 6
   wydania.

### Uwagi

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
node scripts/serve.mjs 8001 localhost /=public /v0.3.0=src --dev-config
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
  **10 poświadczeń** na lekarza (więcej → `bad_args`). `add_credential` przy 10 poświadczeniach
  zwraca `max_credentials` przed pytaniem lekarza; serwer ma ten sam limit (`409 max_credentials`).
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

Procedura (lokalnie i na produkcji, YubiKey 5 w Chrome, Edge i Firefox, tabela wyników) jest w
instrukcji sejfu w repo bobik-2: `docs/runbooks/sejf-kluczy.md`.

## Hosting

Organizacja GitHub **`bobik-2`** (osobna od `iplweb`), repo `bobik-2.github.io`. W tej organizacji
**nie może** być żadnych innych stron Pages — dzieliłyby origin z sejfem. Wymuszone 2FA na
kluczach sprzętowych, minimum właścicieli, chroniona `main` z wymaganym zielonym CI i podpisanymi
commitami, podpisane tagi; deploy tylko z `main` (polityka środowiska `github-pages`).
