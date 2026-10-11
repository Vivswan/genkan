// The native-messaging boundary, exercised adversarially: parseBridgeReq must
// refuse anything that is not a well-formed, catalogued, correctly-argued
// bridge request - and must keep working for everything the host actually
// sends. Each row carries the whole result, so the refusal text, which id is
// echoed, and the request that comes out are all pinned at once. This is the
// proof that the runtime validation fails closed.

import { describe, expect, test } from "bun:test";
import { BridgeRespSchema } from "../generated/envelope";
import { type ParseBridgeReqResult, parseBridgeReq } from "../src/envelope";

describe("parseBridgeReq", () => {
  // An id is echoed on a refusal only when the envelope found no fault with it: a
  // missing, mistyped, fractional, or unsafe-integer id would make the refusal
  // response itself malformed, so those rows carry no id.
  const cases: readonly [string, unknown, ParseBridgeReqResult][] = [
    [
      "a plain tab op is accepted with its typed args",
      { id: 1, op: "tab_focus", args: { tabId: 7 } },
      { ok: true, req: { id: 1, op: "tab_focus", args: { tabId: 7 } } },
    ],
    [
      "the optional browser field and empty args are accepted",
      { id: 2, op: "page_text", browser: "brave", args: {} },
      { ok: true, req: { id: 2, op: "page_text", browser: "brave", args: {} } },
    ],
    [
      "a string id is accepted (forward-compat per the contract)",
      { id: "req-9", op: "tab_list", args: {} },
      { ok: true, req: { id: "req-9", op: "tab_list", args: {} } },
    ],
    [
      // The contract allows it; the handler decides what missing targets mean.
      "optional args omitted (page_click with neither ref nor selector) are accepted",
      { id: 3, op: "page_click", args: {} },
      { ok: true, req: { id: 3, op: "page_click", args: {} } },
    ],
    [
      "null is refused without an id",
      null,
      {
        ok: false,
        error: "malformed bridge request: Invalid input: expected object, received null",
      },
    ],
    [
      "undefined is refused without an id",
      undefined,
      {
        ok: false,
        error: "malformed bridge request: Invalid input: expected object, received undefined",
      },
    ],
    [
      "a number is refused without an id",
      42,
      {
        ok: false,
        error: "malformed bridge request: Invalid input: expected object, received number",
      },
    ],
    [
      "a bare op string is refused without an id",
      "tab_list",
      {
        ok: false,
        error: "malformed bridge request: Invalid input: expected object, received string",
      },
    ],
    [
      "an array is refused without an id",
      [],
      {
        ok: false,
        error: "malformed bridge request: Invalid input: expected object, received array",
      },
    ],
    [
      "a boolean is refused without an id",
      true,
      {
        ok: false,
        error: "malformed bridge request: Invalid input: expected object, received boolean",
      },
    ],
    [
      "a missing id is refused without an id",
      { op: "tab_list", args: {} },
      { ok: false, error: "malformed bridge request: id: Invalid input" },
    ],
    [
      "a missing op is refused with the id echoed",
      { id: 1, args: {} },
      {
        ok: false,
        id: 1,
        error: "malformed bridge request: op: Invalid input: expected string, received undefined",
      },
    ],
    [
      "missing args are refused with the id echoed",
      { id: 1, op: "tab_list" },
      {
        ok: false,
        id: 1,
        error: "malformed bridge request: args: Invalid input: expected object, received undefined",
      },
    ],
    [
      "a mistyped id is refused and not echoed",
      { id: { evil: true }, op: "tab_list", args: {} },
      { ok: false, error: "malformed bridge request: id: Invalid input" },
    ],
    [
      "a fractional id is refused and not echoed, even beside another fault",
      { id: 1.5, op: "tab_list", args: {}, extra: 1 },
      { ok: false, error: "malformed bridge request: id: Invalid input" },
    ],
    [
      "an unsafe-integer id is refused and not echoed",
      { id: 2 ** 60, op: "tab_list", args: {} },
      {
        ok: false,
        error: "malformed bridge request: id: Too big: expected int to be <=9007199254740991",
      },
    ],
    [
      "an unknown top-level field is refused (strict envelope) with the id echoed",
      { id: 1, op: "tab_list", args: {}, extra: "field" },
      { ok: false, id: 1, error: 'malformed bridge request: Unrecognized key: "extra"' },
    ],
    [
      "a browser label outside the contract charset is refused",
      { id: 1, op: "tab_list", args: {}, browser: "a b" },
      {
        ok: false,
        id: 1,
        error:
          "malformed bridge request: browser: Invalid string: must match pattern /^[A-Za-z0-9._-]+$/",
      },
    ],
    [
      "a browser label over the contract length is refused",
      { id: 1, op: "tab_list", args: {}, browser: "x".repeat(33) },
      {
        ok: false,
        id: 1,
        error:
          "malformed bridge request: browser: Too big: expected string to have <=32 characters",
      },
    ],
    [
      "args outside the contract union are refused with the id echoed",
      { id: 4, op: "tab_list", args: { notAnArg: 1 } },
      { ok: false, id: 4, error: 'malformed bridge request: args: Unrecognized key: "notAnArg"' },
    ],
    [
      "an op not in the catalogue is refused by name",
      { id: 5, op: "steal_cookies", args: {} },
      { ok: false, id: 5, error: "unknown op: steal_cookies" },
    ],
    [
      "a required arg missing is refused by the per-op validator",
      { id: 6, op: "page_eval", args: {} },
      {
        ok: false,
        id: 6,
        error:
          "invalid args for page_eval: code: Invalid input: expected string, received undefined",
      },
    ],
    [
      // tabId is typed in the OpArgs union itself, so the envelope refuses it
      // before the per-op validator even runs.
      "a required arg mistyped is caught at the envelope layer already",
      { id: 7, op: "tab_focus", args: { tabId: "7" } },
      {
        ok: false,
        id: 7,
        error:
          "malformed bridge request: args.tabId: Invalid input: expected number, received string",
      },
    ],
    [
      // `url` is a legal OpArgs field, but not a page_eval field: the per-op
      // validator rejects it even though the envelope accepts the union.
      "another op's args smuggled in are refused by the per-op validator",
      { id: 8, op: "page_eval", args: { code: "1", url: "https://x.example" } },
      { ok: false, id: 8, error: 'invalid args for page_eval: Unrecognized key: "url"' },
    ],
  ];
  test.each(cases)("%s", (_, msg, expected) => {
    expect(parseBridgeReq(msg)).toEqual(expected);
  });
});

describe("BridgeRespSchema", () => {
  const cases: readonly [string, unknown, boolean][] = [
    [
      "an ok response with free-form data is accepted",
      { id: 1, ok: true, data: { any: "thing" } },
      true,
    ],
    ["an error response is accepted", { id: 1, ok: false, error: "nope" }, true],
    ["a response without ok is rejected", { id: 1 }, false],
    ["a non-boolean ok is rejected", { id: 1, ok: "yes" }, false],
    ["an unknown field is rejected (strict)", { id: 1, ok: true, extra: 1 }, false],
  ];
  test.each(cases)("%s", (_, response, accepted) => {
    expect(BridgeRespSchema.safeParse(response).success).toBe(accepted);
  });
});
