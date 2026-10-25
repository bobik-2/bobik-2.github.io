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
