import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { walk } from "../../scripts/sums.mjs";

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'";
const files = (await walk("src")).filter((f) => !f.split(/[\\/]/).includes("vendor"));

it("kod sejfu nie wstawia HTML-a ani nie wykonuje tekstu (Review Focus 2)", () => {
  const offenders = [];
  for (const f of files.filter((f) => f.endsWith(".js"))) {
    const text = readFileSync(f, "utf8");
    for (const re of [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/, /document\.write/, /\beval\(/, /new Function\(/]) {
      if (re.test(text)) offenders.push(`${f}: ${re}`);
    }
  }
  expect(offenders).toEqual([]);
});

it("strony sejfu: CSP z specu, bez skryptów, stylów i handlerów inline", () => {
  const offenders = [];
  for (const f of files.filter((f) => f.endsWith(".html"))) {
    const text = readFileSync(f, "utf8");
    if (!text.includes(`content="${CSP}"`)) offenders.push(`${f}: CSP`);
    if (/<script(?![^>]*\bsrc=)[^>]*>/i.test(text)) offenders.push(`${f}: <script> bez src`);
    if (/\son[a-z]+\s*=/i.test(text)) offenders.push(`${f}: atrybut on…`);
    if (/\sstyle\s*=/i.test(text)) offenders.push(`${f}: atrybut style`);
  }
  expect(offenders).toEqual([]);
});
