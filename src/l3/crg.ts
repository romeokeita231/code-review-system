import type { ChangeEvent } from "../contracts/index.js";
import type { RunConfig } from "../contracts/index.js";
import type { TriageAnalysis, TriageProvider } from "../contracts/index.js";
import { execaRunner, type CommandRunner } from "./semgrep.js";
import { asNumber, asRecord, asString } from "./json.js";

export interface CrgOptions {
  root: string;
  runner?: CommandRunner;
  /** Executable that provides the `code-review-graph` CLI. */
  command?: string;
}

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function normalize(value: string, root: string): string {
  const norm = toPosix(value);
  const base = toPosix(root).replace(/\/$/, "");
  return base.length > 0 && norm.startsWith(`${base}/`) ? norm.slice(base.length + 1) : norm;
}

export function degradedAnalysis(changedFiles: string[]): TriageAnalysis {  return {
    changedFiles,
    impactedFiles: changedFiles.length,
    impactedNodes: 0,
    truncated: true,
    unresolvedCallSites: 0,
    indexReady: false,
    indexStale: false,
  };
}

/** `unresolved_call_sites` is a count in JSON envelopes and an array in the CLI. */
function unresolvedCount(value: unknown): number {
  if (Array.isArray(value)) return value.length;
  return asNumber(value) ?? 0;
}

export function analyzeStatic(changedFiles: string[], payload: unknown, root = ""): TriageAnalysis {
  const doc = asRecord(payload);
  if (doc === null) return degradedAnalysis(changedFiles);
  const status = asString(doc["status"]) ?? "ok";
  if (status === "error" || status === "failed") return degradedAnalysis(changedFiles);

  const changed = changedFiles.map(toPosix);
  const impacted = Array.isArray(doc["impacted_files"])
    ? doc["impacted_files"].filter((item): item is string => typeof item === "string")
    : [];
  const union = new Set(changed);
  for (const file of impacted) {
    const norm = root.length > 0 ? normalize(file, root) : toPosix(file);
    if (!changed.includes(norm)) union.add(norm);
  }
  const count = asNumber(doc["impacted_file_count"]);
  const impactedFiles = impacted.length > 0 ? union.size : Math.max(changed.length, count ?? 0);
  const impactedNodes = Math.max(0, Math.trunc(asNumber(doc["total_impacted"]) ?? 0));
  const unresolved = Math.max(0, unresolvedCount(doc["unresolved_call_sites"]));
  const stale = status === "partial";

  return {
    changedFiles,
    impactedFiles,
    impactedNodes,
    truncated: doc["truncated"] === true || stale,
    unresolvedCallSites: unresolved,
    indexReady: true,
    indexStale: stale,
  };
}

export class CrgTriage implements TriageProvider {
  private readonly root: string;
  private readonly runner: CommandRunner;
  private readonly command: string;
  private readonly queryMs: number;

  constructor(config: RunConfig, opts: CrgOptions) {
    this.root = opts.root;
    this.runner = opts.runner ?? execaRunner;
    this.command = opts.command ?? process.env["CRG_COMMAND"] ?? config.sources.crg.command;
    this.queryMs = config.budgets.crgQueryMs;
  }

  async analyze(event: ChangeEvent, deadline: number): Promise<TriageAnalysis> {
    const changedFiles = event.files ?? [];

    const remaining = deadline - Date.now();
    if (remaining <= 0) return degradedAnalysis(changedFiles);
    const timeoutMs = Math.min(this.queryMs, remaining);

    let result;
    try {
      result = await this.runner.run({
        file: this.command,
        args: ["impact", "--repo", this.root, "--files", ...changedFiles],
        cwd: this.root,
        timeoutMs,
      });
    } catch {
      return degradedAnalysis(changedFiles);
    }

    if (result.timedOut || result.exitCode !== 0) {
      return degradedAnalysis(changedFiles);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return degradedAnalysis(changedFiles);
    }

    return analyzeStatic(changedFiles, parsed, this.root);
  }
}

export function createCrgTriage(config: RunConfig, opts: CrgOptions): CrgTriage {
  return new CrgTriage(config, opts);
}
