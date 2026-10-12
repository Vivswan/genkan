#!/usr/bin/env bun
// Every tool has one pin and one provisioner, or local runs and CI drift apart without a failure:
//   bun     .bun-version (platform-managed); proto's bun plugin detects it, and a .prototools pin would
//           override it silently, since proto reads .prototools before the tool's own version file
//   rust    rust-toolchain.toml through rustup; proto's rust plugin registers a toolchain without a rustc
//   python  .python-version through uv; proto's python plugin would be a second provisioner
// proto, moon, node, and uv are pinned in .prototools alone and CI reads them from there
// (.github/actions/setup-moon, the Containerfile).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "./lib.ts";

export function toolchainMismatches(root: string): string[] {
  const mismatches: string[] = [];
  const fail = (message: string): void => {
    mismatches.push(message);
  };

  const prototools = Bun.TOML.parse(readFileSync(join(root, ".prototools"), "utf8")) as Record<
    string,
    unknown
  >;
  // A pin is a top-level string; anything under a [table] is a setting, not a pin.
  const pin = (tool: string): string | undefined =>
    typeof prototools[tool] === "string" ? prototools[tool] : undefined;

  if (pin("bun") !== undefined) {
    fail(
      ".prototools pins bun - .bun-version is its only pin (proto detects it, and a .prototools pin overrides it silently)",
    );
  }
  if (pin("rust") !== undefined) {
    fail(
      ".prototools pins rust - rust-toolchain.toml is its only pin (proto's install breaks rustup's)",
    );
  }
  const settings = prototools.settings;
  const builtinPlugins =
    typeof settings === "object" && settings !== null
      ? (settings as Record<string, unknown>)["builtin-plugins"]
      : undefined;
  if (!Array.isArray(builtinPlugins)) {
    fail(
      ".prototools settings.builtin-plugins allow-list is missing (proto would provision python and rust)",
    );
  } else {
    for (const tool of ["python", "rust"]) {
      if (builtinPlugins.includes(tool)) {
        fail(
          `.prototools builtin-plugins includes ${tool} - ${tool === "python" ? "python is owned by uv (.python-version)" : "rust is owned by rustup (rust-toolchain.toml)"}`,
        );
      }
    }
  }
  return mismatches;
}

if (import.meta.main) {
  const mismatches = toolchainMismatches(repoRoot);
  for (const mismatch of mismatches) console.error(`MISMATCH: ${mismatch}`);
  if (mismatches.length === 0) console.log("toolchain pins consistent");
  process.exit(mismatches.length === 0 ? 0 : 1);
}
