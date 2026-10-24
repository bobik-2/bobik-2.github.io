// Składa publikowane drzewo: dist/ = public/* + v<VERSION>/ = src/*,
// plus dist/SHA256SUMS. Bez bundlera — kopiowanie 1:1, więc build jest
// odtwarzalny z definicji; CI i tak sprawdza dwa buildy.
import { createHash } from "node:crypto";
import { cp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { VERSION } from "../src/config.js";

const out = process.argv[2] ?? "dist";
await rm(out, { recursive: true, force: true });
await cp("public", out, { recursive: true });
await cp("src", join(out, `v${VERSION}`), { recursive: true });

const files = (await walk(out)).sort();
const lines = [];
for (const f of files) {
  const sum = createHash("sha256").update(await readFile(f)).digest("hex");
  lines.push(`${sum}  ${relative(out, f)}`);
}
await writeFile(join(out, "SHA256SUMS"), lines.join("\n") + "\n");
console.log(`dist: ${files.length} plików, wersja ${VERSION}`);

async function walk(dir) {
  const res = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) res.push(...(await walk(p)));
    else res.push(p);
  }
  return res;
}
