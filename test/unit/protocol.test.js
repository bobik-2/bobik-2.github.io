import { describe, expect, it } from "vitest";
import { errorResponse, okResponse, parseRequest } from "../../src/protocol.js";

describe("parseRequest", () => {
  it("przyjmuje poprawne żądanie", () => {
    expect(parseRequest({ v: 1, id: "a", op: "hello" })).toMatchObject({ op: "hello" });
  });

  it.each([
    [null, "bad_message"],
    [[], "bad_message"],
    [{ v: 2, id: "a", op: "hello" }, "bad_version"],
    [{ v: 1, id: "", op: "hello" }, "bad_id"],
    [{ v: 1, id: "a", op: 3 }, "bad_op"],
  ])("odrzuca %j kodem %s", (data, code) => {
    expect(() => parseRequest(data)).toThrow(expect.objectContaining({ code }));
  });
});

it("koperty odpowiedzi", () => {
  expect(okResponse("a", 1)).toEqual({ v: 1, id: "a", ok: true, result: 1 });
  expect(errorResponse("a", "x")).toEqual({ v: 1, id: "a", ok: false, error: "x" });
});
