// The two release-gate facts GitHub never reports, each shown firing on a hand-written workflow set: a job
// with no timeout-minutes (also one reached through a local `uses:` call; a remote call and a timeout given
// as an expression are not findings), and a caller count other than one, where only a workflow whose
// header says the platform manages it is exempt. Nothing here reads the repository's own workflows: the
// check script does, under `moon run check-release-gate`.
import { describe, expect, test } from "bun:test";
import { findings, GATE, type Workflows } from "../check-release-gate";

function workflows(files: Record<string, string>): Workflows {
  return new Map(
    Object.entries(files).map(([file, text]) => [
      file,
      { doc: Bun.YAML.parse(text) as never, text },
    ]),
  );
}

const gate = `
on: workflow_call
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 20
    steps: [{ run: "true" }]
  installers:
    uses: ./.github/workflows/installers.yml
`;
const installers = `
on: workflow_call
jobs:
  installer:
    runs-on: ubuntu-latest
    timeout-minutes: 40
    steps: [{ run: "true" }]
`;
const nightly = `
on: { schedule: [{ cron: "0 0 * * *" }] }
jobs:
  release-gate:
    uses: ./.github/workflows/release-gate.yml
`;
const managedCi = `
# This file is managed by Vivswan/repo-platform.
on: pull_request
jobs:
  release-gate:
    uses: ./.github/workflows/release-gate.yml
`;

describe("check-release-gate", () => {
  const cases: [label: string, files: Record<string, string>, expected: string[]][] = [
    [
      "the shape the repository ships",
      { [GATE]: gate, "installers.yml": installers, "nightly.yml": nightly, "ci.yml": managedCi },
      [],
    ],
    [
      "a job without a timeout",
      {
        [GATE]: gate.replace("    timeout-minutes: 20\n", ""),
        "installers.yml": installers,
        "nightly.yml": nightly,
      },
      ["release-gate.yml#build: no timeout-minutes (GitHub's default is six hours)"],
    ],
    [
      "a job without a timeout behind a uses: call",
      {
        [GATE]: gate,
        "installers.yml": installers.replace("    timeout-minutes: 40\n", ""),
        "nightly.yml": nightly,
      },
      ["installers.yml#installer: no timeout-minutes (GitHub's default is six hours)"],
    ],
    [
      "only the managed caller: zero repository-owned callers",
      { [GATE]: gate, "installers.yml": installers, "ci.yml": managedCi },
      [
        "release-gate.yml has 0 repository-owned caller(s) []; exactly one is expected, a second runs the gate twice",
      ],
    ],
    [
      "a timeout given as an expression, and a remote reusable call, are not findings",
      {
        [GATE]: gate
          .replace("timeout-minutes: 20", `timeout-minutes: \${{ matrix.minutes }}`)
          .replace(
            "uses: ./.github/workflows/installers.yml",
            "uses: octo/tools/.github/workflows/build.yml@main",
          ),
        "nightly.yml": nightly,
      },
      [],
    ],
    [
      "the managed marker inside a step body does not exempt a caller",
      {
        [GATE]: gate,
        "installers.yml": installers,
        "nightly.yml": nightly,
        "checks.yml": `${nightly.replace("release-gate:", "gate:")}  note:\n    runs-on: ubuntu-latest\n    timeout-minutes: 1\n    steps: [{ run: "echo managed by Vivswan/repo-platform" }]\n`,
      },
      [
        "release-gate.yml has 2 repository-owned caller(s) [checks.yml#gate, nightly.yml#release-gate]; exactly one is expected, a second runs the gate twice",
      ],
    ],
    [
      "a second repository-owned caller",
      {
        [GATE]: gate,
        "installers.yml": installers,
        "nightly.yml": nightly,
        "checks.yml": nightly.replace("release-gate:", "gate:"),
      },
      [
        "release-gate.yml has 2 repository-owned caller(s) [checks.yml#gate, nightly.yml#release-gate]; exactly one is expected, a second runs the gate twice",
      ],
    ],
  ];
  test.each(cases)("%s", (_label, files, expected) => {
    expect(findings(workflows(files))).toEqual(expected);
  });
});
