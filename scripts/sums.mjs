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
