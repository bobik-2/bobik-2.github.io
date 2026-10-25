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
