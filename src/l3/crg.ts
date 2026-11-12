import type { ChangeEvent } from "../contracts/index.js";
import type { RunConfig } from "../contracts/index.js";
import type { TriageAnalysis, TriageProvider } from "../l2/index.js";
import { execaRunner, type CommandRunner } from "./semgrep.js";

export interface CrgOptions {
  root: string;
  runner?: CommandRunner;
  python?: string;
}

const QUERY_BUDGET_MS = 300;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function normalize(value: string, root: string): string {
  const norm = toPosix(value);
  const base = toPosix(root).replace(/\/$/, "");
  return base.length > 0 && norm.startsWith(`${base}/`) ? norm.slice(base.length + 1) : norm;
}

export function degradedAnalysis(changedFiles: string[]): TriageAnalysis {
  return {
    changedFiles,
    impactedFiles: changedFiles.length,
    impactedNodes: 0,
    truncated: true,
    unresolvedCallSites: 0,
    indexReady: false,
    indexStale: false,
  };
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
  const unresolved = Math.max(0, Math.trunc(asNumber(doc["unresolved_call_sites"]) ?? 0));
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
  private readonly python: string;
  private readonly readiness = new Map<string, boolean>();

  constructor(_config: RunConfig, opts: CrgOptions) {
    this.root = opts.root;
    this.runner = opts.runner ?? execaRunner;
    this.python = opts.python ?? process.env["CRG_PYTHON"] ?? "python";
  }

  async analyze(event: ChangeEvent, deadline: number): Promise<TriageAnalysis> {
    const changedFiles = event.files ?? [];
    if (this.readiness.get(this.root) === false) return degradedAnalysis(changedFiles);

    const remaining = deadline - Date.now();
    if (remaining <= 0) return degradedAnalysis(changedFiles);
    const timeoutMs = Math.min(QUERY_BUDGET_MS, remaining);

    let result;
    try {
      result = await this.runner.run({
        file: this.python,
        args: [
          "-m",
          "crg",
          "impact-radius",
          "--repo",
          this.root,
          "--changed-files",
          changedFiles.join(","),
          "--format",
          "json",
        ],
        cwd: this.root,
        timeoutMs,
      });
    } catch {
      this.readiness.set(this.root, false);
      return degradedAnalysis(changedFiles);
    }

    if (result.timedOut || result.exitCode !== 0) {
      this.readiness.set(this.root, false);
      return degradedAnalysis(changedFiles);
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      this.readiness.set(this.root, false);
      return degradedAnalysis(changedFiles);
    }

    const analysis = analyzeStatic(changedFiles, parsed, this.root);
    this.readiness.set(this.root, analysis.indexReady);
    return analysis;
  }
}

export function createCrgTriage(config: RunConfig, opts: CrgOptions): CrgTriage {
  return new CrgTriage(config, opts);
}
