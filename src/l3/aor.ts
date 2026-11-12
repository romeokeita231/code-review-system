import { createHash } from "node:crypto";
import type {
  Finding,
  RunConfig,
  SignalSource,
  SourceResult,
  SourceReviewInput,
  SourceStatus,
} from "../contracts/index.js";
import { execaRunner, type CommandRunner } from "./semgrep.js";
import { addedLines, intersectsAdded, repoPath } from "./diff.js";
import { asNumber, asRecord, asString } from "./json.js";

export interface AorOptions {
  root: string;
  runner?: CommandRunner;
}

function firstLine(text: string): string {
  const line = (text.trim().split("\n")[0] ?? "").trim();
  return line.slice(0, 200);
}

function collectPaths(value: unknown, into: Set<string>): void {
  if (typeof value === "string") {
    into.add(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) collectPaths(item, into);
    return;
  }
  const record = asRecord(value);
  if (record === null) return;
  const named = asString(record["path"]) ?? asString(record["file"]);
  if (named !== null) into.add(named);
}

function previewPaths(stdout: string): Set<string> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  const envelope = asRecord(parsed);
  if (envelope === null) return null;
  const files = new Set<string>();
  for (const key of ["files", "paths", "preview_files", "predicted"]) {
    if (envelope[key] !== undefined) collectPaths(envelope[key], files);
  }
  const manifest = asRecord(envelope["manifest"]);
  if (manifest !== null) {
    for (const key of ["files", "paths"]) {
      if (manifest[key] !== undefined) collectPaths(manifest[key], files);
    }
  }
  return files;
}

function severityOf(comment: Record<string, unknown>): number {
  const raw = (asString(comment["priority"]) ?? asString(comment["severity"]) ?? "").toUpperCase();
  if (raw === "P1" || raw === "ERROR" || raw === "CRITICAL" || raw === "HIGH") return 3;
  if (raw === "P2" || raw === "WARNING" || raw === "MEDIUM") return 2;
  return 1;
}

function confidenceOf(comment: Record<string, unknown>): number {
  const value = asNumber(comment["confidence"]);
  if (value !== null && value >= 0 && value <= 1) return value;
  return 0.6;
}

function blank(
  status: SourceStatus,
  errorKind: string | null,
  startedAt: number,
  filesCovered: number,
  filesUnknown: number,
  tokens: number | null = null,
  findings: Finding[] = [],
  tokenDetail: SourceResult["tokenDetail"] = null,
): SourceResult {
  return {
    source: "aor",
    status,
    findings,
    coverage: { filesCovered, filesUnknown },
    tokens,
    tokenDetail,
    latencyMs: Math.max(0, Date.now() - startedAt),
    errorKind,
  };
}

export class AorSource implements SignalSource {
  readonly name = "aor" as const;

  private readonly config: RunConfig;
  private readonly root: string;
  private readonly runner: CommandRunner;

  constructor(config: RunConfig, opts: AorOptions) {
    this.config = config;
    this.root = opts.root;
    this.runner = opts.runner ?? execaRunner;
  }

  async review(input: SourceReviewInput): Promise<SourceResult> {
    const startedAt = Date.now();
    const config = this.config.sources.aor;
    const targets = [...new Set((input.event.files ?? []).map((file) => repoPath(this.root, file)))];
    const targetSet = new Set(targets);
    const added = addedLines(input.event.diff);

    const remaining = input.deadline - Date.now();
    const outerMs = Math.min(remaining, config.outerCapMs);
    if (outerMs <= 0) return blank("timeout", "deadline", startedAt, 0, targets.length);

    const chunks = Math.min(
      config.maxChunks,
      Math.max(1, Math.ceil(targets.length / Math.max(1, config.concurrency))),
    );
    const perWaveMs = Math.min(outerMs / chunks, config.timeoutPerFileMs);
    const timeoutMinutes = Math.max(1, Math.floor(perWaveMs / 60000));
    const tokenBudget = input.tier === 1 ? config.tierTokens.tier1 : config.tierTokens.tier2;

    const reasons: string[] = [];
    if (config.preview.enabled) {
      const previewMs = Math.min(outerMs, Math.floor(outerMs * config.preview.budgetSwitchRatio));
      try {
        const preview = await this.runner.run({
          file: config.command,
          args: [
            "scan",
            "--path",
            targets.join(","),
            "--preview",
            "--format",
            "json",
            "--concurrency",
            String(config.concurrency),
            "--timeout",
            String(timeoutMinutes),
            "--no-summary",
          ],
          cwd: this.root,
          timeoutMs: previewMs,
        });
        const predicted = preview.timedOut ? null : previewPaths(preview.stdout);
        if (predicted === null) {
          reasons.push("preview_unknown");
        } else {
          const unaccounted = [...predicted].filter(
            (file) => !targetSet.has(repoPath(this.root, file)),
          );
          if (unaccounted.length > 0) reasons.push(`files_unaccounted:${unaccounted.length}`);
        }
      } catch {
        reasons.push("preview_failed");
      }
    }

    let result;
    try {
      result = await this.runner.run({
        file: config.command,
        args: [
          "scan",
          "--path",
          targets.join(","),
          "--format",
          "json",
          "--audience",
          "agent",
          "--concurrency",
          String(config.concurrency),
          "--timeout",
          String(timeoutMinutes),
          "--no-summary",
          "--max-tokens-budget",
          String(tokenBudget),
          ...(input.tier === 2 ? ["--max-tools", String(config.tier2MaxTools)] : []),
        ],
        cwd: this.root,
        timeoutMs: outerMs,
      });
    } catch {
      return blank("error", "spawn_error", startedAt, 0, targets.length);
    }

    if (result.timedOut) return blank("timeout", "timeout", startedAt, 0, targets.length);

    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return blank("error", "half_parsed", startedAt, 0, targets.length);
    }

    const envelope = asRecord(parsed);
    if (envelope === null) return blank("error", "payload_missing", startedAt, 0, targets.length);

    const statusRaw = asString(envelope["status"]);
    if (statusRaw === null) return blank("error", "payload_missing", startedAt, 0, targets.length);

    if (statusRaw === "failed") return blank("error", "failed", startedAt, 0, targets.length);
    if (
      statusRaw !== "success" &&
      statusRaw !== "completed_with_warnings" &&
      statusRaw !== "completed_with_errors" &&
      statusRaw !== "skipped"
    ) {
      return blank("error", "unknown_status", startedAt, 0, targets.length);
    }

    const summary = asRecord(envelope["summary"]);
    const manifest = asRecord(envelope["manifest"]);
    const coverage = asRecord(manifest?.["coverage"]);
    const failedCoverage = Array.isArray(coverage?.["failed"]) ? coverage["failed"].length : 0;

    const filesReviewed = asNumber(summary?.["files_reviewed"]) ?? 0;
    const budgetExceeded = summary?.["budget_exceeded"] === true;
    const incomplete = asNumber(summary?.["files_incomplete"]) ?? failedCoverage;
    const missing = Math.max(0, targets.length - filesReviewed);
    const filesComplete = statusRaw === "skipped" || (missing === 0 && !budgetExceeded && incomplete === 0);

    const rawComments = envelope["comments"];
    if (rawComments !== undefined && !Array.isArray(rawComments)) {
      return blank("error", "payload_missing", startedAt, 0, targets.length);
    }

    const findings: Finding[] = [];
    let dropped = 0;
    const comments = Array.isArray(rawComments) ? rawComments : [];
    for (const raw of comments) {
      const comment = asRecord(raw);
      if (comment === null) {
        dropped += 1;
        continue;
      }
      const rawFile = asString(comment["path"]);
      const start = asNumber(comment["start_line"]);
      const end = asNumber(comment["end_line"]);
      if (rawFile === null || start === null || end === null) {
        dropped += 1;
        continue;
      }
      const file = repoPath(this.root, rawFile);
      if (!targetSet.has(file)) {
        dropped += 1;
        continue;
      }
      if (!intersectsAdded(added, file, start, end)) {
        dropped += 1;
        continue;
      }
      if (start === 0 && end === 0) {
        dropped += 1;
        continue;
      }
      const existing = asString(comment["existing_code"]) ?? "";
      if (existing.trim().length === 0) {
        dropped += 1;
        continue;
      }
      const evidence = firstLine(existing);
      if (evidence.length === 0) {
        dropped += 1;
        continue;
      }
      const title = firstLine(asString(comment["content"]) ?? "");
      const hash = createHash("sha1")
        .update(`${file}\u0000${start}\u0000${end}\u0000${title}`)
        .digest("hex")
        .slice(0, 16);
      findings.push({
        file,
        startLine: start,
        endLine: end,
        severity: severityOf(comment),
        confidence: confidenceOf(comment),
        source: "aor",
        cwe: null,
        evidence,
        rawId: `aor:${hash}`,
      });
    }

    const tokenTotal = asNumber(summary?.["total_tokens"]);
    const tokens = tokenTotal !== null ? Math.max(0, Math.trunc(tokenTotal)) : null;
    const tokenDetail = {
      total: tokens,
      input: asNumber(summary?.["input_tokens"]),
      output: asNumber(summary?.["output_tokens"]),
      cacheRead: asNumber(summary?.["cache_read_input_tokens"]),
      cacheWrite: asNumber(summary?.["cache_creation_input_tokens"]),
    };
    const filesUnknown = filesComplete
      ? Math.max(0, targets.length - filesReviewed)
      : Math.max(missing, incomplete, targets.length > 0 ? 1 : 0);

    let status: SourceStatus = "ok";
    if (statusRaw === "completed_with_warnings") {
      status = "degraded";
      reasons.push("warnings");
    }
    if (statusRaw === "completed_with_errors") {
      status = "degraded";
      reasons.push("completed_with_errors");
    }
    if (!filesComplete) {
      if (status === "ok") status = "degraded";
      reasons.push(budgetExceeded ? "budget_exceeded" : "partial");
    }
    if (dropped > 0) reasons.push(`dropped:${dropped}/${comments.length}`);

    return blank(
      status,
      reasons.length > 0 ? reasons.join(";") : null,
      startedAt,
      Math.min(filesReviewed, targets.length),
      filesUnknown,
      tokens,
      findings,
      tokenDetail,
    );
  }
}

export function createAorSource(config: RunConfig, opts: AorOptions): AorSource {
  return new AorSource(config, opts);
}
