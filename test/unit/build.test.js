import { execFileSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = process.cwd();
const INDEX_HTML = (links = "") => `<!doctype html>\n<title>t</title>\n<ul>${links}</ul>\n`;
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
  writeFileSync(join(dir, "public/index.html"), INDEX_HTML());
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

  // Końcowy przegląd, I-2 / M-6: korzeń originu sejfu z gita (nie z dysku), dokładna allowlista,
  // schemat revoked.json, index.html bez skryptów.
  it("korzeń originu z git archive HEAD: plik nieśledzony nie trafia do dist/", () => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "public/evil.html"), "<script>alert(1)</script>\n");
    writeFileSync(join(r.dir, "public/revoked.json"), '{"revoked": ["1.0.0"]}\n'); // niezacommitowane
    r.build();
    expect(existsSync(join(r.dir, "dist/evil.html"))).toBe(false);
    expect(read(r, "dist/revoked.json")).toBe('{"revoked": []}\n');
    expect(read(r, "dist/SHA256SUMS")).not.toContain("evil.html");
  });

  it("plik spoza allowlisty w public/ -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    mkdirSync(join(r.dir, "public/sub"));
    writeFileSync(join(r.dir, "public/sub/x.js"), "1\n");
    r.commit();
    expect(r.buildError()).toContain("public/sub/x.js: spoza allowlisty");
  });

  it("brak pliku z allowlisty -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    r.git("rm", "-q", "public/index.html");
    r.commit();
    expect(r.buildError()).toContain("brak public/index.html");
  });

  it.each([
    ["nie JSON", "{revoked: []}"],
    ["bez tablicy", '{"revoked": "0.9.0"}'],
    ["brak klucza revoked", "{}"],
    ["nadmiarowy klucz", '{"revoked": [], "x": 1}'],
    ["wpis nie X.Y.Z", '{"revoked": ["0.9"]}'],
    ["wpis nie tekst", '{"revoked": [1]}'],
    ["tablica zamiast obiektu", "[]"],
  ])("revoked.json %s -> błąd", (_name, body) => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "public/revoked.json"), `${body}\n`);
    r.commit();
    expect(r.buildError()).toContain("public/revoked.json: oczekiwano {\"revoked\": [\"X.Y.Z\", …]}");
  });

  it("index.html ze skryptem -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "public/index.html"), INDEX_HTML('<SCRIPT src="x.js"></SCRIPT>'));
    r.commit();
    expect(r.buildError()).toContain("public/index.html: zawiera <script");
  });

  // Końcowy przegląd, M-3: korzeń nie może wskazywać niezbudowanej wersji, a dist/ musi mieć wersję,
  // która nie jest unieważniona.
  it("link z index.html do zbudowanej wersji -> ok; do niezbudowanej -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "public/index.html"), INDEX_HTML('<li><a href="v1.0.0/demo.html">d</a></li>'));
    r.commit();
    r.build();
    writeFileSync(join(r.dir, "public/index.html"), INDEX_HTML('<li><a href="v1.1.0/demo.html">d</a></li>'));
    r.commit();
    expect(r.buildError()).toContain("public/index.html: link do niezbudowanej wersji v1.1.0");
  });

  it("wszystkie zbudowane wersje unieważnione -> błąd", () => {
    const r = makeRepo();
    r.release("1.0.0");
    writeFileSync(join(r.dir, "public/revoked.json"), '{"revoked": ["1.0.0"]}\n');
    r.commit();
    expect(r.buildError()).toContain("brak zbudowanej wersji spoza public/revoked.json");
  });
});
