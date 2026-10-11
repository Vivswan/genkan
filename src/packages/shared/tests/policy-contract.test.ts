// Semantics of the generated policy contract (generated/policy.ts): the deny
// baseline and the strict document, values, and overlay validators, each a
// table of inputs and whether it admits them. The SOURCE is the Rust core
// (src/packages/core/src/policy/mod.rs) and the module is rebuilt from it
// before this suite runs, so these tests own the semantics, not the
// provenance: Rust-parity bounds and the cross-language golden vectors.

import { describe, expect, test } from "bun:test";
import type { z } from "zod";
import { POLICY_GOLDEN_FIXTURE } from "../generated/enclave-fixture";
import {
  DISABLED_TOOL_NAME_MAX_BYTES,
  DISABLED_TOOLS_MAX_ENTRIES,
  isPolicyFieldName,
  POLICY_DEFAULTS,
  POLICY_DOC_VERSION,
  POLICY_DOMAIN,
  POLICY_REVISION_MAX,
  PolicyDocSchema,
  PolicyOverlaySchema,
  PolicyValuesSchema,
} from "../generated/policy";

// A well-formed v1 document: the deny-baseline values under default scoping.
const wellFormedDoc = () => ({
  v: POLICY_DOC_VERSION,
  revision: 1,
  touched: ["pageEvalEnabled"],
  ...POLICY_DEFAULTS,
});

describe("POLICY_DEFAULTS", () => {
  test("is deep-frozen, nested array included", () => {
    expect(Object.isFrozen(POLICY_DEFAULTS)).toBe(true);
    expect(Object.isFrozen(POLICY_DEFAULTS.disabledTools)).toBe(true);
  });
});

// Each row: what it pins, the input, and whether the schema admits it. An
// admitted input parses to itself: the strict schemas invent no default and
// drop no field, so an accepted row also pins the parsed document.
type SchemaRow = readonly [string, unknown, boolean];
function pinsAdmission(schema: z.ZodType, rows: readonly SchemaRow[]) {
  test.each(rows)("%s", (_, input, accepted) => {
    expect(schema.safeParse(input)).toEqual(
      accepted ? { success: true, data: input } : { success: false, error: expect.anything() },
    );
  });
}

describe("PolicyDocSchema", () => {
  const docWith = (mutation: Record<string, unknown>) => ({ ...wellFormedDoc(), ...mutation });
  const atCap = Array.from({ length: DISABLED_TOOLS_MAX_ENTRIES }, (_, i) => `tool_${i}`);
  // The Rust parser bounds the millisecond fields to JS_SAFE_INT_MAX for exactly
  // this equivalence; a value only one side accepts would sign host-side and
  // brick the push extension-side.
  const msFields = [
    "hostReverifyMs",
    "confirmGraceMs",
    "clickToastTimeoutMs",
    "evalToastTimeoutMs",
  ];
  pinsAdmission(PolicyDocSchema, [
    ["a well-formed document is accepted and parses to itself", docWith({}), true],
    ["an unknown field is rejected, fail-closed", docWith({ surprise: true }), false],
    [
      "a revision at the JS-safe bound is accepted",
      docWith({ revision: POLICY_REVISION_MAX }),
      true,
    ],
    [
      "a revision beyond the JS-safe bound is rejected",
      docWith({ revision: POLICY_REVISION_MAX + 1 }),
      false,
    ],
    [
      "a touched set naming the retired requireEnrollment is rejected",
      docWith({ touched: ["requireEnrollment"] }),
      false,
    ],
    ["a later document version is rejected", docWith({ v: 2 }), false],
    ["an earlier document version is rejected", docWith({ v: 0 }), false],
    ...msFields.flatMap((field): SchemaRow[] => [
      [
        `${field} at the JS-safe bound is accepted (Rust parity)`,
        docWith({ [field]: Number.MAX_SAFE_INTEGER }),
        true,
      ],
      [
        `${field} beyond the JS-safe bound is rejected (Rust parity)`,
        docWith({ [field]: Number.MAX_SAFE_INTEGER + 1 }),
        false,
      ],
    ]),
    [
      "disabledTools at the entry cap is accepted (Rust parity)",
      docWith({ disabledTools: atCap }),
      true,
    ],
    [
      "disabledTools one over the entry cap is rejected (Rust parity)",
      docWith({ disabledTools: [...atCap, "one_more"] }),
      false,
    ],
  ]);
});

describe("PolicyValuesSchema", () => {
  const valuesWith = (disabledTools: string[]) => ({ ...POLICY_DEFAULTS, disabledTools });
  pinsAdmission(PolicyValuesSchema, [
    [
      "a tool name at the byte cap is accepted (Rust parity)",
      valuesWith(["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES)]),
      true,
    ],
    [
      "a tool name one over the byte cap is rejected (Rust parity)",
      valuesWith(["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)]),
      false,
    ],
    ["an empty tool name is rejected", valuesWith([""]), false],
  ]);
});

describe("PolicyOverlaySchema", () => {
  pinsAdmission(PolicyOverlaySchema, [
    ["the empty overlay is accepted and invents no value for an absent field", {}, true],
    [
      "an all-owned subset is accepted",
      { pageEvalEnabled: false, confirmGraceMs: 0, disabledTools: ["page_eval"] },
      true,
    ],
    ["the retired requireEnrollment is rejected, fail-closed", { requireEnrollment: false }, false],
    [
      "a settings field the catalogue does not own is rejected, fail-closed",
      { uiLanguage: "en" },
      false,
    ],
    [
      "a millisecond field at the JS-safe bound is accepted (Rust parity)",
      { confirmGraceMs: Number.MAX_SAFE_INTEGER },
      true,
    ],
    [
      "a millisecond field beyond the JS-safe bound is rejected (Rust parity)",
      { confirmGraceMs: Number.MAX_SAFE_INTEGER + 1 },
      false,
    ],
    ["a negative millisecond field is rejected", { hostReverifyMs: -1 }, false],
    ["an empty tool name is rejected", { disabledTools: [""] }, false],
    [
      "a tool name one over the byte cap is rejected (Rust parity)",
      { disabledTools: ["a".repeat(DISABLED_TOOL_NAME_MAX_BYTES + 1)] },
      false,
    ],
  ]);
});

// The POLICY_DOMAIN golden vectors (generated/enclave-fixture.ts): the byte-level
// proof that the Rust signer and this side's verify-then-parse pipeline
// agree. The extension's golden test replays these through its own
// verifier; here the fixture's internal consistency and the document parse
// are pinned at the shared layer.
describe("POLICY_GOLDEN_FIXTURE", () => {
  const b64ToBytes = (b64: string) => Uint8Array.from(Buffer.from(b64, "base64"));
  const hexToBytes = (hex: string) => Uint8Array.from(Buffer.from(hex, "hex"));

  test("each message is POLICY_DOMAIN || 0x00 || the exact document bytes", () => {
    for (const vector of POLICY_GOLDEN_FIXTURE.vectors) {
      const domain = new TextEncoder().encode(POLICY_DOMAIN);
      const doc = b64ToBytes(vector.docB64);
      const expected = new Uint8Array([...domain, 0, ...doc]);
      expect(hexToBytes(vector.messageHex)).toEqual(expected);
    }
  });

  test("each document strict-parses under the generated PolicyDocSchema", () => {
    const revisions = POLICY_GOLDEN_FIXTURE.vectors.map((vector) => {
      const doc = PolicyDocSchema.parse(
        JSON.parse(new TextDecoder().decode(b64ToBytes(vector.docB64))),
      );
      expect(doc.v).toBe(POLICY_DOC_VERSION);
      for (const field of doc.touched) expect(isPolicyFieldName(field)).toBe(true);
      return doc.revision;
    });
    // The fixture carries distinct revisions, so replay-ordering tests have
    // a lower and a higher baseline to work with.
    expect(new Set(revisions).size).toBe(revisions.length);
  });

  test("each signature verifies over the message bytes (WebCrypto, P-256/SHA-256)", async () => {
    const key = await crypto.subtle.importKey(
      "raw",
      b64ToBytes(POLICY_GOLDEN_FIXTURE.pubkeyB64),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    for (const vector of POLICY_GOLDEN_FIXTURE.vectors) {
      const ok = await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        key,
        b64ToBytes(vector.sigB64),
        hexToBytes(vector.messageHex),
      );
      expect(ok).toBe(true);
      // And a flipped byte in the document breaks it: the signature really
      // covers these exact bytes.
      const tampered = hexToBytes(vector.messageHex);
      const last = tampered.length - 1;
      tampered[last] = (tampered[last] ?? 0) ^ 1;
      expect(
        await crypto.subtle.verify(
          { name: "ECDSA", hash: "SHA-256" },
          key,
          b64ToBytes(vector.sigB64),
          tampered,
        ),
      ).toBe(false);
    }
  });
});
