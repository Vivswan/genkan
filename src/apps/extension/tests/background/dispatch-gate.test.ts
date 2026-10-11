// The dispatcher's disable gate: a catalogued tool in disabledTools throws its
// refusal; everything else passes through, an unknown op included (Rust
// validates tool names upstream and the port boundary owns that contract, so
// the gate never fail-closes a name it does not know).

import { describe, expect, test } from "vitest";
import { assertNotDisabled } from "@/lib/background/dispatch";

/** The thrown message, or null when the call returns: the gate's whole outcome as one value. */
function thrownMessage(call: () => void): string | null {
  try {
    call();
    return null;
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
}

describe("dispatch disable-gate (assertNotDisabled)", () => {
  const cases: readonly [string, string | undefined, string[], string | null][] = [
    [
      "a known tool in the disabled list throws the exact legacy message",
      "tab_list",
      ["tab_list"],
      "tool disabled in settings: tab_list",
    ],
    ["a known tool with nothing disabled passes", "tab_list", [], null],
    ["a known tool passes while another tool is disabled", "tab_list", ["page_eval"], null],
    [
      "an unknown op passes even when its own name is in the disabled list",
      "does_not_exist",
      ["does_not_exist"],
      null,
    ],
    ["an undefined op passes", undefined, ["tab_list"], null],
    ["an empty op passes", "", [], null],
  ];
  test.each(cases)("%s", (_, op, disabledTools, expected) => {
    expect(thrownMessage(() => assertNotDisabled(op, disabledTools))).toBe(expected);
  });
});
