// Podmiana listy originów panelu w src/config.js przy lokalnym serwowaniu (dev, E2E, B3).
// Nigdy w buildzie: dist/ powstaje z `git archive` podpisanych tagów (rozstrzygnięcia 11 i 12).

// Atrapa panelu (testy sejfu) i dev bobik-2 (docker compose / runserver na :8000).
export const DEV_PARENT_ORIGINS = Object.freeze(["http://127.0.0.1:8000", "http://localhost:8000"]);

const OPEN = "// <parent-origins>";
const CLOSE = "// </parent-origins>";
const BLOCK = /(\/\/ <parent-origins>\n)[\s\S]*?(\n[ \t]*\/\/ <\/parent-origins>)/;
const ORIGIN = /^https?:\/\/[a-z0-9.-]+(:\d{1,5})?$/;

export function rewriteParentOrigins(text, origins) {
  if (text.split(OPEN).length !== 2 || text.split(CLOSE).length !== 2 || !BLOCK.test(text)) {
    throw new Error("src/config.js: oczekiwano dokładnie jednego bloku // <parent-origins> … // </parent-origins>");
  }
  for (const origin of origins) {
    if (!ORIGIN.test(origin)) throw new Error(`nieprawidłowy origin panelu: ${origin}`);
  }
  const lines = origins.map((o) => `  ${JSON.stringify(o)}, // dev/E2E (scripts/serve.mjs)`).join("\n");
  return text.replace(BLOCK, (_match, open, close) => `${open}${lines}${close}`);
}
