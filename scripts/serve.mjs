// Minimalny serwer statyczny do testów (bez zależności).
// Użycie: node scripts/serve.mjs <port> <host> <prefiks>=<katalog> [...]
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve } from "node:path";

const TYPES = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json",
};

const [port, host, ...mountArgs] = process.argv.slice(2);
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
  try {
    if ((await stat(file)).isDirectory()) file = join(file, "index.html");
    const body = await readFile(file);
    res.writeHead(200, { "content-type": TYPES[extname(file)] ?? "application/octet-stream", "cache-control": "no-store" });
    res.end(body);
  } catch {
    notFound(res);
  }
}).listen(Number(port), host);

function notFound(res) {
  res.writeHead(404);
  res.end();
}
