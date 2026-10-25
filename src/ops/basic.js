// hello i lock — jedyne operacje bez kluczy.

export const hello = {
  needs: "none",
  interactive: false,
  parse: () => ({}),
  async run(ctx) {
    return { version: ctx.version, revoked: ctx.refusal === "revoked", browser_ok: ctx.browserOk, prf: await ctx.prf, state: ctx.state };
  },
};

export const lock = {
  needs: "ready",
  interactive: false,
  parse: () => ({}),
  async run(ctx) {
    ctx.lock("user");
    return {};
  },
};
