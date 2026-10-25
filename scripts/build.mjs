// Składa publikowane drzewo (rozstrzygnięcie 12): dist/ = public/ z `git archive HEAD public`
// + v<X.Y.Z>/ z KAŻDEGO podpisanego tagu vX.Y.Z (`git archive <tag> src`), plus dist/SHA256SUMS.
// Wydane wersje są niezmienne i żyją równolegle; wycofuje się je wpisem w public/revoked.json,
// nie usunięciem. Korzeń originu dzieli origin z sejfem, więc idzie z gita (nie z dysku), wyłącznie
// z allowlisty plików, bez skryptów, z poprawnym revoked.json (końcowy przegląd, I-2, M-3, M-6).
// Użycie: node scripts/build.mjs [katalog=dist]
import { existsSync } from "node:fs";
import { readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { assertInHistory, BuildError, extractSrc, extractTree, filesAt, releaseTags, showAt, sumsAt, verifySignedTag, versionAt } from "./release-lib.mjs";
import { sumsOf } from "./sums.mjs";

const SIGNERS = "releases/allowed_signers";
const PUBLIC_FILES = ["index.html", "revoked.json"];
const VERSION_RE = /^\d+\.\d+\.\d+$/;
const REVOKED_SHAPE = 'public/revoked.json: oczekiwano {"revoked": ["X.Y.Z", …]}';
const out = process.argv[2] ?? "dist";

try {
  await build(out);
} catch (e) {
  // BuildError = naruszona reguła wydań (komunikat dla człowieka); każdy inny wyjątek to błąd skryptu.
  if (!(e instanceof BuildError)) throw e;
  console.error(`Błąd builda: ${e.message}`);
  process.exit(1);
}

function parseRevoked(text) {
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    // SyntaxError: plik nie jest JSON-em — sejf w każdej wersji odmówiłby pracy (M-6).
    if (e instanceof SyntaxError) throw new BuildError(REVOKED_SHAPE);
    throw e;
  }
  const ok =
    doc !== null &&
    typeof doc === "object" &&
    !Array.isArray(doc) &&
    Object.keys(doc).length === 1 &&
    Array.isArray(doc.revoked) &&
    doc.revoked.every((v) => typeof v === "string" && VERSION_RE.test(v));
  if (!ok) throw new BuildError(REVOKED_SHAPE);
  return doc.revoked;
}

// Korzeń originu z HEAD: dokładnie pliki z allowlisty, revoked.json wg schematu, index.html bez skryptów.
function checkPublic() {
  const files = filesAt("HEAD", "public");
  for (const f of files) {
    if (!PUBLIC_FILES.includes(f)) throw new BuildError(`public/${f}: spoza allowlisty (${PUBLIC_FILES.join(", ")})`);
  }
  for (const f of PUBLIC_FILES) {
    if (!files.includes(f)) throw new BuildError(`brak public/${f}`);
  }
  const revoked = parseRevoked(showAt("HEAD", "public/revoked.json"));
  const html = showAt("HEAD", "public/index.html");
  if (/<script/i.test(html)) throw new BuildError("public/index.html: zawiera <script");
  const links = [...html.matchAll(/href="v(\d+\.\d+\.\d+)\//g)].map((m) => m[1]);
  return { revoked, links };
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
  const { revoked, links } = checkPublic();

  await rm(target, { recursive: true, force: true });
  extractTree("HEAD", "public", target);
  const built = [];
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
    built.push(version);
  }

  if (prepared.includes(current) && (await sumsAt("HEAD")) !== (await readFile(`releases/${current}.sha256`, "utf8"))) {
    throw new BuildError(
      tags.includes(`v${current}`)
        ? `src/ zmieniony po wydaniu v${current} — podbij VERSION w src/config.js`
        : `releases/${current}.sha256 nieaktualne wobec src/ (node scripts/release-sums.mjs HEAD)`,
    );
  }
  for (const version of links) {
    if (!built.includes(version)) throw new BuildError(`public/index.html: link do niezbudowanej wersji v${version}`);
  }
  if (!built.some((v) => !revoked.includes(v))) throw new BuildError("brak zbudowanej wersji spoza public/revoked.json");

  await writeFile(join(target, "SHA256SUMS"), await sumsOf(target, { exclude: ["SHA256SUMS"] }));
  console.log(`dist: ${tags.join(", ")}`);
}
