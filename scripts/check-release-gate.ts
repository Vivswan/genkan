#!/usr/bin/env bun
// Two facts about the release gate that nothing else reports. A job with no timeout-minutes runs up to
// GitHub's six-hour default and no check names the omission; a second repository-owned caller of
// release-gate.yml runs the whole gate twice with no error. GitHub itself rejects the rest at call time
// (inputs, secrets, a permission above the caller's), and actionlint covers the syntax.

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { die, repoRoot } from "./lib.ts";

export const GATE = "release-gate.yml";
const MANAGED_MARKER = "managed by Vivswan/repo-platform";

/** True when the file's leading comment block (the platform's header) says the sync owns it. */
function isManaged(text: string): boolean {
  const header: string[] = [];
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    if (!line.startsWith("#")) break;
    header.push(line);
  }
  return header.join("\n").includes(MANAGED_MARKER);
}

interface Job {
  readonly uses?: unknown;
  readonly "timeout-minutes"?: unknown;
}
interface Workflow {
  readonly jobs?: Record<string, Job | null>;
}
/** Workflow file name -> its parsed document and raw text. */
export type Workflows = ReadonlyMap<string, { readonly doc: Workflow; readonly text: string }>;

export function readWorkflows(dir: string): Workflows {
  const out = new Map<string, { doc: Workflow; text: string }>();
  for (const file of readdirSync(dir)
    .filter((f) => f.endsWith(".yml") || f.endsWith(".yaml"))
    .sort()) {
    const text = readFileSync(join(dir, file), "utf8");
    const doc = Bun.YAML.parse(text);
    if (doc === null || typeof doc !== "object") die(`${file}: not a YAML mapping`);
    out.set(file, { doc: doc as Workflow, text });
  }
  return out;
}

/** The local workflow a `uses: ./.github/workflows/<file>` job calls, else undefined. */
function calledWorkflow(job: Job): string | undefined {
  const uses = typeof job.uses === "string" ? job.uses : undefined;
  const match = uses?.match(/^\.\/\.github\/workflows\/([^/@]+)$/);
  return match?.[1];
}

/**
 * Every `<file>#<job>` reached from `entry` whose timeout-minutes is absent. A `uses:` job cannot carry a
 * timeout of its own: a local call is judged by the called workflow's jobs, a remote one by its owner. A
 * local target that is missing is GitHub's error at call time, not a job without a timeout.
 */
export function jobsMissingTimeout(
  workflows: Workflows,
  entry: string,
  seen = new Set<string>(),
): string[] {
  if (seen.has(entry)) return [];
  seen.add(entry);
  const missing: string[] = [];
  for (const [name, job] of Object.entries(workflows.get(entry)?.doc.jobs ?? {})) {
    if (!job) continue;
    if (typeof job.uses === "string") {
      const called = calledWorkflow(job);
      if (called !== undefined) missing.push(...jobsMissingTimeout(workflows, called, seen));
    } else if (job["timeout-minutes"] === undefined || job["timeout-minutes"] === null) {
      missing.push(`${entry}#${name}`);
    }
  }
  return missing;
}

/** Every `<file>#<job>` in a repository-owned workflow (no managed header) that calls the gate. */
export function gateCallers(workflows: Workflows): string[] {
  const callers: string[] = [];
  for (const [file, { doc, text }] of workflows) {
    if (isManaged(text)) continue;
    for (const [name, job] of Object.entries(doc.jobs ?? {})) {
      if (job && calledWorkflow(job) === GATE) callers.push(`${file}#${name}`);
    }
  }
  return callers.sort();
}

export function findings(workflows: Workflows): string[] {
  const out = jobsMissingTimeout(workflows, GATE).map(
    (job) => `${job}: no timeout-minutes (GitHub's default is six hours)`,
  );
  const callers = gateCallers(workflows);
  if (callers.length !== 1) {
    out.push(
      `${GATE} has ${callers.length} repository-owned caller(s) [${callers.join(", ")}]; exactly one is expected, a second runs the gate twice`,
    );
  }
  return out;
}

if (import.meta.main) {
  const problems = findings(readWorkflows(join(repoRoot, ".github/workflows")));
  for (const problem of problems) console.error(`check-release-gate: ${problem}`);
  if (problems.length > 0) process.exit(1);
  console.log(
    `check-release-gate: every ${GATE} job has a timeout and one repository-owned job calls it`,
  );
}
