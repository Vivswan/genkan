import { afterEach, describe, expect, test } from "bun:test";
import { toolchainMismatches } from "../check-toolchain";
import { Scratch, writeTree } from "../lib";

const scratch = new Scratch();
afterEach(() => scratch.remove());

// What would drift silently: proto reads .prototools before a tool's own version file, so a bun pin there
// would replace the platform-managed .bun-version with no failure anywhere; and proto's allow-list must
// leave python to uv and rust to rustup, or two provisioners own one tool.
describe("toolchainMismatches", () => {
  const prototools = (pins: string, settings = '[settings]\nbuiltin-plugins = ["bun", "moon"]\n') =>
    `# the header comment\n${pins}\n${settings}`;
  const cases: ReadonlyArray<readonly [name: string, prototools: string, mismatches: string[]]> = [
    ["one pin per tool", prototools('proto = "0.1.0"\n'), []],
    [
      ".prototools pins bun",
      prototools('proto = "0.1.0"\nbun = "1.2.3"\n'),
      [
        ".prototools pins bun - .bun-version is its only pin (proto detects it, and a .prototools pin overrides it silently)",
      ],
    ],
    [
      ".prototools pins rust",
      prototools('proto = "0.1.0"\nrust = "1.80.0"\n'),
      [
        ".prototools pins rust - rust-toolchain.toml is its only pin (proto's install breaks rustup's)",
      ],
    ],
    [
      "the allow-list is missing",
      prototools('proto = "0.1.0"\n', ""),
      [
        ".prototools settings.builtin-plugins allow-list is missing (proto would provision python and rust)",
      ],
    ],
    [
      "the allow-list names the tools other provisioners own",
      prototools('proto = "0.1.0"\n', '[settings]\nbuiltin-plugins = ["bun", "python", "rust"]\n'),
      [
        ".prototools builtin-plugins includes python - python is owned by uv (.python-version)",
        ".prototools builtin-plugins includes rust - rust is owned by rustup (rust-toolchain.toml)",
      ],
    ],
  ];

  test.each(cases)("%s", (_name, file, mismatches) => {
    const root = scratch.dir("toolchain");
    writeTree(root, { ".prototools": file });
    expect(toolchainMismatches(root)).toEqual(mismatches);
  });
});
