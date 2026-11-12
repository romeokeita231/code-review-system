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

export interface AorOptions {
  root: string;
  runner?: CommandRunner;
}

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

function firstLine(text: string): string {
  const line = (text.trim().split("\n")[0] ?? "").trim();
  return line.slice(0, 200);
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
): SourceResult {
  return {
    source: "aor",
    status,
    findings,
    coverage: { filesCovered, filesUnknown },
    tokens,
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
    const targets = [...new Set(input.event.files ?? [])];

    const remaining = input.deadline - Date.now();
    const outerMs = Math.min(remaining, config.outerCapMs);
    if (outerMs <= 0) return blank("timeout", "deadline", startedAt, 0, targets.length);

    const chunks = Math.max(1, Math.ceil(targets.length / Math.max(1, config.concurrency)));
    const timeoutMinutes = Math.max(1, Math.floor(outerMs / 60000 / chunks));
    const tokenBudget = input.tier === 1 ? config.tierTokens.tier1 : config.tierTokens.tier2;

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
      const file = asString(comment["path"]);
      const start = asNumber(comment["start_line"]);
      const end = asNumber(comment["end_line"]);
      if (file === null || start === null || end === null) {
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
    const filesUnknown = filesComplete
      ? Math.max(0, targets.length - filesReviewed)
      : Math.max(missing, incomplete, targets.length > 0 ? 1 : 0);

    const reasons: string[] = [];
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
    );
  }
}

export function createAorSource(config: RunConfig, opts: AorOptions): AorSource {
  return new AorSource(config, opts);
}
