// Limit odszyfrowań (spec B, rozstrzygnięcie 1). Liczy otwarte wywiady (rozpakowane DEK) i osobno
// wartości SealedToClinic. Wartości zmienia wyłącznie nowy release sejfu. Zegar wstrzykiwany.
export const LIMITS = Object.freeze({
  INTERVIEWS_PER_UNLOCK: 50,
  NEW_INTERVIEWS_PER_WINDOW: 10,
  NEW_INTERVIEWS_WINDOW_MS: 5 * 60_000,
  STC_PER_UNLOCK: 500,
  STC_PER_WINDOW: 100,
  STC_WINDOW_MS: 60_000,
  IDLE_MS: 15 * 60_000,
  MAX_AGE_MS: 8 * 60 * 60_000,
  INTERACTION_TIMEOUT_MS: 120_000,
  OPEN_MAX_ITEMS: 1000,
  // Poświadczenia (YubiKeye) jednego lekarza; serwer bobik-2 ma ten sam limit (409 max_credentials).
  MAX_CREDENTIALS: 10,
});

export function createLimiter(now) {
  let startedAt = null;
  let lastActivity = null;
  let counted = new Set();
  let stcTotal = 0;
  let interviewTimes = [];
  let stcTimes = [];

  function clear() {
    counted = new Set();
    stcTotal = 0;
    interviewTimes = [];
    stcTimes = [];
  }
  function prune(t) {
    interviewTimes = interviewTimes.filter((x) => t - x < LIMITS.NEW_INTERVIEWS_WINDOW_MS);
    stcTimes = stcTimes.filter((x) => t - x.t < LIMITS.STC_WINDOW_MS);
  }
  const fresh = (ids) => [...new Set(ids)].filter((id) => !counted.has(id));

  return {
    start() {
      startedAt = now();
      lastActivity = startedAt;
      clear();
    },
    reset() {
      startedAt = null;
      lastActivity = null;
      clear();
    },
    touch() {
      lastActivity = now();
    },
    // Czysta ocena żądania przed odszyfrowaniem; limit sesji ma pierwszeństwo przed oknem.
    verdict({ interviewIds = [], stc = 0 }) {
      prune(now());
      const n = fresh(interviewIds).length;
      if (counted.size + n > LIMITS.INTERVIEWS_PER_UNLOCK || stcTotal + stc > LIMITS.STC_PER_UNLOCK) return "limit_reached";
      const stcInWindow = stcTimes.reduce((sum, x) => sum + x.n, 0);
      if (interviewTimes.length + n > LIMITS.NEW_INTERVIEWS_PER_WINDOW || stcInWindow + stc > LIMITS.STC_PER_WINDOW) return "rate_limited";
      return "ok";
    },
    record({ interviewIds = [], stc = 0 }) {
      const t = now();
      for (const id of fresh(interviewIds)) {
        counted.add(id);
        interviewTimes.push(t);
      }
      if (stc > 0) {
        stcTotal += stc;
        stcTimes.push({ t, n: stc });
      }
    },
    expired() {
      if (startedAt === null) return null;
      const t = now();
      if (t - startedAt >= LIMITS.MAX_AGE_MS) return "max_age";
      if (t - lastActivity >= LIMITS.IDLE_MS) return "idle";
      return null;
    },
    snapshot() {
      return {
        interviews: counted.size,
        stc: stcTotal,
        idleLeftMs: startedAt === null ? null : Math.max(0, LIMITS.IDLE_MS - (now() - lastActivity)),
      };
    },
  };
}
