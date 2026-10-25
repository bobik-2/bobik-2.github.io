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
