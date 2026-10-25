import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const SCRIPTS = ["build.mjs", "release-lib.mjs", "release-sums.mjs", "sums.mjs"];
const run = (cwd, cmd, args) => execFileSync(cmd, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

// Tymczasowe repo z własnym kluczem SSH (bez kluczy użytkownika) i skryptami builda z tego repo.
function makeRepo() {
  const dir = mkdtempSync(join(tmpdir(), "sejf-build-"));
  run(dir, "ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "test", "-f", join(dir, ".key")]);
  const git = (...args) => run(dir, "git", args);
  git("init", "-q", "-b", "main");
  for (const [key, value] of [
    ["user.name", "Test"],
    ["user.email", "test@example.com"],
    ["commit.gpgsign", "false"],
    ["tag.gpgsign", "false"],
    ["gpg.format", "ssh"],
    ["user.signingkey", join(dir, ".key")],
  ]) git("config", key, value);
  for (const d of ["scripts", "src", "public", "releases"]) mkdirSync(join(dir, d));
  for (const f of SCRIPTS) cpSync(join(ROOT, "scripts", f), join(dir, "scripts", f));
  writeFileSync(join(dir, ".gitignore"), ".key\n.key.pub\ndist/\n");
  writeFileSync(join(dir, "releases/allowed_signers"), `test@example.com namespaces="git" ${readFileSync(join(dir, ".key.pub"), "utf8").trim()}\n`);
  writeFileSync(join(dir, "public/revoked.json"), '{"revoked": []}\n');
  const repo = {
    dir,
    git,
    write(version, body = "a") {
      writeFileSync(join(dir, "src/config.js"), `export const VERSION = "${version}";\n`);
      writeFileSync(join(dir, "src/a.js"), `export const A = "${body}";\n`);
    },
    commit(message = "zmiana") {
      git("add", "-A");
      git("commit", "-q", "-m", message);
    },
    prepare(version) {
      writeFileSync(join(dir, `releases/${version}.sha256`), run(dir, "node", ["scripts/release-sums.mjs", "HEAD"]));
      repo.commit(`sumy ${version}`);
    },
    signTag(version) {
      git("tag", "-s", `v${version}`, "-m", `v${version}`);
    },
    release(version, body) {
      repo.write(version, body);
      repo.commit();
      repo.prepare(version);
      repo.signTag(version);
    },
    build() {
      return run(dir, "node", ["scripts/build.mjs", "dist"]);
    },
    buildError() {
      try {
        repo.build();
      } catch (e) {
        return e.stderr;
      }
      throw new Error("build miał paść");
    },
  };
  return repo;
}

const read = (r, path) => readFileSync(join(r.dir, path), "utf8");

describe("build z podpisanych tagów (rozstrzygnięcie 12, Review Focus 5)", { timeout: 60_000 }, () => {
  it("podpisany tag + sumy -> dist/v<X>/ i SHA256SUMS", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.build();
    expect(read(r, "dist/v1.0.0/a.js")).toBe('export const A = "a";\n');
    expect(read(r, "dist/SHA256SUMS")).toContain("  v1.0.0/a.js\n");
    expect(read(r, "dist/SHA256SUMS")).toContain("  revoked.json\n");
  });

  it("dwa buildy dają te same sumy (odtwarzalność)", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.build();
    const first = read(r, "dist/SHA256SUMS");
    r.build();
    expect(read(r, "dist/SHA256SUMS")).toBe(first);
  });

  it("wydane wersje żyją równolegle", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.release("1.1.0", "b");
    r.build();
    expect(read(r, "dist/v1.0.0/a.js")).toContain('"a"');
    expect(read(r, "dist/v1.1.0/a.js")).toContain('"b"');
  });

  it("przygotowany release (sumy bez taga) bieżącej wersji -> ok, jeszcze niepublikowany", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.write("1.1.0", "b");
    r.commit();
    r.prepare("1.1.0");
    r.build();
    expect(existsSync(join(r.dir, "dist/v1.0.0"))).toBe(true);
    expect(existsSync(join(r.dir, "dist/v1.1.0"))).toBe(false);
  });

  it("brak tagów -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    expect(r.buildError()).toContain("brak tagów v*");
  });

  it("tag w złym formacie -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.git("tag", "-s", "v1.0", "-m", "v1.0");
    expect(r.buildError()).toContain("tag v1.0: oczekiwano vX.Y.Z");
  });

  it("tag bez podpisu -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    r.prepare("1.0.0");
    r.git("tag", "-a", "v1.0.0", "-m", "v1.0.0");
    expect(r.buildError()).toContain("v1.0.0: brak ważnego podpisu");
  });

  it("tag spoza historii HEAD -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.git("checkout", "-q", "-b", "boczna");
    r.release("1.0.1", "x");
    r.git("checkout", "-q", "main");
    expect(r.buildError()).toContain("v1.0.1: tag spoza historii HEAD");
  });

  it("tag bez pliku sum -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    r.signTag("1.0.0");
    expect(r.buildError()).toContain("v1.0.0: brak releases/1.0.0.sha256");
  });

  it("sumy niezgodne z treścią taga -> błąd", () => {
    const r = makeRepo();
    r.write("1.0.0");
    r.commit();
    writeFileSync(join(r.dir, "releases/1.0.0.sha256"), `${"0".repeat(64)}  a.js\n`);
    r.commit("złe sumy");
    r.signTag("1.0.0");
    expect(r.buildError()).toContain("v1.0.0: treść różni się od releases/1.0.0.sha256");
  });

  it("zmiana src/ wydanej wersji bez podbicia VERSION -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.write("1.0.0", "zmienione");
    r.commit();
    expect(r.buildError()).toContain("src/ zmieniony po wydaniu v1.0.0");
  });

  it("nieaktualne sumy przygotowanego release'u -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.write("1.1.0", "b");
    r.commit();
    r.prepare("1.1.0");
    r.write("1.1.0", "c");
    r.commit();
    expect(r.buildError()).toContain("releases/1.1.0.sha256 nieaktualne");
  });

  it("sumy bez taga dla wersji innej niż bieżąca -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "releases/0.9.0.sha256"), "x\n");
    r.commit();
    expect(r.buildError()).toContain("releases/0.9.0.sha256 bez tagu v0.9.0");
  });
});
