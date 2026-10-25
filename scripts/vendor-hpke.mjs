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
