import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { walk } from "../../scripts/sums.mjs";

const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'";
const files = (await walk("src")).filter((f) => !f.split(/[\\/]/).includes("vendor"));

// Przegląd 9–10, I-3: także srcdoc, createContextualFragment, setHTMLUnsafe, DOMParser, setAttribute("on…").
const SINKS = [
  /\.innerHTML\b/,
  /\.outerHTML\b/,
  /insertAdjacentHTML/,
  /document\.write/,
  /\beval\(/,
  /new Function\(/,
  /\bsrcdoc\b/,
  /createContextualFragment/,
  /setHTMLUnsafe/,
  /parseHTMLUnsafe/,
  /\bDOMParser\b/,
  /setAttribute\(\s*["'`]on/i,
];

it("kontrola pozytywna: każde wyrażenie łapie swój sink", () => {
  const samples = [
    "el.innerHTML = x",
    "el.outerHTML = x",
    "el.insertAdjacentHTML('beforeend', x)",
    "document.write(x)",
    "eval(x)",
    "new Function(x)",
    "frame.srcdoc = x",
    "range.createContextualFragment(x)",
    "el.setHTMLUnsafe(x)",
    "Document.parseHTMLUnsafe(x)",
    "new DOMParser().parseFromString(x, 'text/html')",
    'el.setAttribute("onclick", x)',
  ];
  expect(SINKS.map((re, i) => re.test(samples[i]))).toEqual(SINKS.map(() => true));
  expect(/setAttribute\(\s*["'`]on/i.test("el.setAttribute('ONERROR', x)")).toBe(true);
});

it("kod sejfu nie wstawia HTML-a ani nie wykonuje tekstu (Review Focus 2)", () => {
  const offenders = [];
  for (const f of files.filter((f) => f.endsWith(".js"))) {
    const text = readFileSync(f, "utf8");
    for (const re of SINKS) {
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
