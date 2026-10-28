import { describe, expect, it } from "vitest";
import { createLimiter, LIMITS } from "../../src/limits.js";

const MIN = 60_000;
const ids = (n, from = 0) => Array.from({ length: n }, (_, i) => `w${from + i}`);

function setup() {
  const clock = { t: 1_000_000 };
  const limiter = createLimiter(() => clock.t);
  limiter.start();
  return { clock, l: limiter };
}

describe("limit odszyfrowań (rozstrzygnięcie 1, V-5)", () => {
  it("wartości z tabeli specu", () => {
    expect(LIMITS).toEqual({
      INTERVIEWS_PER_UNLOCK: 50,
      NEW_INTERVIEWS_PER_WINDOW: 10,
      NEW_INTERVIEWS_WINDOW_MS: 5 * MIN,
      STC_PER_UNLOCK: 500,
      STC_PER_WINDOW: 100,
      STC_WINDOW_MS: MIN,
      IDLE_MS: 15 * MIN,
      MAX_AGE_MS: 8 * 60 * MIN,
      INTERACTION_TIMEOUT_MS: 120_000,
      OPEN_MAX_ITEMS: 1000,
      MAX_CREDENTIALS: 10,
    });
    expect(Object.isFrozen(LIMITS)).toBe(true);
  });

  it("10 nowych wywiadów w 5 min przechodzi, 11. -> rate_limited, po oknie znów można", () => {
    const { clock, l } = setup();
    expect(l.verdict({ interviewIds: ids(10) })).toBe("ok");
    l.record({ interviewIds: ids(10) });
    expect(l.verdict({ interviewIds: ids(1, 10) })).toBe("rate_limited");
    clock.t += 5 * MIN;
    expect(l.verdict({ interviewIds: ids(1, 10) })).toBe("ok");
  });

  it("ponowne otwarcie policzonego wywiadu nie zwiększa licznika", () => {
    const { l } = setup();
    l.record({ interviewIds: ids(10) });
    expect(l.verdict({ interviewIds: ids(10) })).toBe("ok");
    l.record({ interviewIds: [...ids(10), "w0"] });
    expect(l.snapshot().interviews).toBe(10);
  });

  it("51. wywiad w sesji -> limit_reached (pierwszeństwo przed rate_limited)", () => {
    const { clock, l } = setup();
    for (let r = 0; r < 5; r++) {
      l.record({ interviewIds: ids(10, r * 10) });
      clock.t += 5 * MIN;
    }
    expect(l.snapshot().interviews).toBe(50);
    expect(l.verdict({ interviewIds: ["nowy"] })).toBe("limit_reached");
  });

  it("STC: 100 na minutę, 500 na sesję", () => {
    const { clock, l } = setup();
    expect(l.verdict({ stc: 100 })).toBe("ok");
    l.record({ stc: 100 });
    expect(l.verdict({ stc: 1 })).toBe("rate_limited");
    for (let i = 0; i < 4; i++) {
      clock.t += MIN;
      l.record({ stc: 100 });
    }
    clock.t += MIN;
    expect(l.verdict({ stc: 1 })).toBe("limit_reached");
    expect(l.verdict({ stc: 0 })).toBe("ok");
  });

  it("jedno żądanie z 501 wartościami -> limit_reached", () => {
    expect(setup().l.verdict({ stc: 501 })).toBe("limit_reached");
  });

  it("bezczynność 15 min -> idle; aktywność odsuwa termin", () => {
    const { clock, l } = setup();
    clock.t += 14 * MIN;
    expect(l.expired()).toBe(null);
    l.touch();
    clock.t += 14 * MIN;
    expect(l.expired()).toBe(null);
    clock.t += MIN;
    expect(l.expired()).toBe("idle");
  });

  it("wiek 8 h -> max_age mimo aktywności", () => {
    const { clock, l } = setup();
    for (let i = 0; i < 47; i++) {
      clock.t += 10 * MIN;
      l.touch();
      expect(l.expired()).toBe(null);
    }
    clock.t += 10 * MIN;
    l.touch();
    expect(l.expired()).toBe("max_age");
  });

  it("snapshot: liczniki i czas do blokady; reset czyści wszystko", () => {
    const { clock, l } = setup();
    l.record({ interviewIds: ids(2), stc: 7 });
    clock.t += 61_000;
    expect(l.snapshot()).toEqual({ interviews: 2, stc: 7, idleLeftMs: 15 * MIN - 61_000 });
    l.reset();
    expect(l.expired()).toBe(null);
    expect(l.snapshot()).toEqual({ interviews: 0, stc: 0, idleLeftMs: null });
  });
});
