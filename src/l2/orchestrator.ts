import type {
  CalibrationArtifact,
  ChangeEvent,
  Disposition,
  Finding,
  MergedFinding,
  ReviewRow,
  ReviewSkipReason,
  ReviewStatus,
  RunConfig,
  SignalSource,
  SourceResult,
  Tier,
  Toolchain,
} from "../contracts/index.js";
import { configHash } from "../config/index.js";
import { fuse, singleSourceProbability } from "../l4/index.js";
import { ledgerFor, planCall, systemClock, type Clock, type TurnBudgetLedger } from "./budget.js";
import { formatMessage, mechanismOf } from "./templates.js";
import { computeTier, staticTier, type TriageResult } from "./triage.js";

export interface TriageAnalysis {
  changedFiles: string[];
  impactedFiles: number;
  impactedNodes: number;
  truncated: boolean;
  unresolvedCallSites: number;
  indexReady: boolean;
  indexStale: boolean;
}

export interface TriageProvider {
  analyze(event: ChangeEvent, deadline: number): Promise<TriageAnalysis>;
}

export interface DenyGroupKey {
  file: string;
  ruleId: string;
}

function groupId(key: DenyGroupKey): string {
  return `${key.file}\u0000${key.ruleId}`;
}

export class DenyGuard {
  private readonly counts = new Map<string, number>();

  check(keys: DenyGroupKey[]): { deny: boolean; blockLoop: boolean } {
    if (keys.length === 0) return { deny: false, blockLoop: false };
    const looping = keys.some((key) => (this.counts.get(groupId(key)) ?? 0) >= 2);
    if (looping) return { deny: false, blockLoop: true };
    for (const key of keys) {
      this.counts.set(groupId(key), (this.counts.get(groupId(key)) ?? 0) + 1);
    }
    return { deny: true, blockLoop: false };
  }

  clear(): void {
    this.counts.clear();
  }
}

export interface ReviewContext {
  runId: string;
  config: RunConfig;
  sources: SignalSource[];
  artifact: CalibrationArtifact | null;
  triage?: TriageProvider | null;
  guard?: DenyGuard;
  clock?: Clock;
  ledger?: TurnBudgetLedger;
  toolchain?: Toolchain;
  sourceText?: Record<string, string>;
}

export interface ReviewOutcome {
  disposition: Disposition;
  row: ReviewRow;
}

function ruleIdOf(finding: Finding): string {
  return finding.rawId.split("\u0000")[0] ?? finding.rawId;
}

function defaultToolchain(config: RunConfig): Toolchain {
  return {
    semgrep: config.sources.semgrep.version,
    aor: config.sources.aor.versionCommit,
    crg: config.sources.crg.command,
    node: process.version,
    platform: process.platform,
  };
}

function costFor(name: string, config: RunConfig): number {
  switch (name) {
    case "semgrep":
      return config.budgets.semgrepKillMs;
    case "crg":
      return config.budgets.crgQueryMs;
    case "registry":
      return config.sources.registry.timeoutMs;
    case "aor":
      return Math.min(config.sources.aor.outerCapMs, config.budgets.callMs);
    default:
      return config.budgets.callMs;
  }
}

interface TierDecision {
  tier: Tier;
  tierSource: Disposition["tierSource"];
  perFileTier: Record<string, Tier>;
  degraded: boolean;
  skipReason: ReviewSkipReason | null;
}

async function decideTier(
  event: ChangeEvent,
  files: string[],
  ctx: ReviewContext,
  deadline: number,
): Promise<TierDecision> {
  const boundaries = { tier0: ctx.config.triage.tier0, tier1: ctx.config.triage.tier1 };
  const uniform = (tier: Tier): Record<string, Tier> =>
    Object.fromEntries(files.map((file) => [file, tier]));

  if (!ctx.config.triage.enabled) {
    return { tier: 2, tierSource: "none", perFileTier: uniform(2), degraded: false, skipReason: null };
  }
  if (!ctx.triage) {
    const tier = staticTier(files.length, boundaries);
    return {
      tier,
      tierSource: "static",
      perFileTier: uniform(tier),
      degraded: true,
      skipReason: "index_not_ready",
    };
  }

  let analysis: TriageAnalysis;
  try {
    analysis = await ctx.triage.analyze(event, deadline);
  } catch {
    const tier = staticTier(files.length, boundaries);
    return {
      tier,
      tierSource: "static",
      perFileTier: uniform(tier),
      degraded: true,
      skipReason: "index_not_ready",
    };
  }

  const computed: TriageResult = computeTier(
    {
      changedFiles: files.length,
      impactedFiles: analysis.impactedFiles,
      impactedNodes: analysis.impactedNodes,
      truncated: analysis.truncated,
      unresolvedCallSites: analysis.unresolvedCallSites,
      indexReady: analysis.indexReady,
      indexStale: analysis.indexStale,
    },
    boundaries,
  );

  const perFileTier: Record<string, Tier> = {};
  for (const file of files) perFileTier[file] = computed.tier;
  for (const file of analysis.changedFiles) {
    if (perFileTier[file] === undefined) perFileTier[file] = Math.max(computed.tier, 1) as Tier;
  }

  return {
    tier: computed.tier,
    tierSource: computed.source,
    perFileTier,
    degraded: computed.degraded,
    skipReason: computed.skipReason,
  };
}

function aggregateStatus(results: SourceResult[], skipped: boolean): ReviewRow["status"] {
  if (results.length === 0) return skipped ? "skipped" : "ok";
  const bad = results.filter((result) => result.status !== "ok");
  if (bad.length === 0) return "ok";
  if (bad.length === results.length) {
    return bad.some((result) => result.status === "timeout") ? "timeout" : "failed";
  }
  return "partial";
}

function reviewStatusOf(results: SourceResult[], skipped: boolean, skipReason: ReviewSkipReason | null): ReviewStatus {
  if (skipped) return "skipped";
  if (skipReason === "index_not_ready" || skipReason === "index_stale") return "degraded";
  return results.some((result) => result.status !== "ok") ? "degraded" : "ok";
}

export async function review(change: ChangeEvent, ctx: ReviewContext): Promise<ReviewOutcome> {
  const clock = ctx.clock ?? systemClock;
  const ledger = ctx.ledger ?? ledgerFor(ctx.config, clock);
  const guard = ctx.guard ?? new DenyGuard();
  const toolchain = ctx.toolchain ?? defaultToolchain(ctx.config);
  const startedAt = clock.now();
  const turn = { sessionId: change.sessionId, rootCallId: change.rootCallId };
  const results: SourceResult[] = [];
  const sourceText = ctx.sourceText ?? {};
  let skipReason: ReviewSkipReason | null = null;
  let skipped = false;
  let mergedFindings: MergedFinding[] = [];

  const base = (): Omit<Disposition, "mechanism" | "finalDisposition"> => ({
    findings: [],
    text: null,
    pSemgrep: null,
    pFused: null,
    preDecision: "not_run",
    postDecision: "not_run",
    reviewStatus: "ok",
    skipReason: null,
    blockLoop: false,
    tier: 0,
    tierSource: "none",
  });

  const finish = (disposition: Disposition): ReviewOutcome => {
    const elapsed = clock.now() - startedAt;
    const tokens = results.reduce<number | null>(
      (acc, result) => (result.tokens === null ? acc : (acc ?? 0) + result.tokens),
      null,
    );
    const row: ReviewRow = {
      run_id: ctx.runId,
      config_hash: configHash(ctx.config),
      baseline: ctx.config.baseline,
      mode: ctx.config.mode,
      change_event: change,
      tier: disposition.tier,
      tier_source: disposition.tierSource,
      sources: results,
      findings_merged: mergedFindings,
      p_semgrep: disposition.pSemgrep,
      p_fused: disposition.pFused,
      pre_decision: disposition.preDecision,
      post_decision: disposition.postDecision,
      final_disposition: disposition.finalDisposition,
      review_status: disposition.reviewStatus,
      review_skip_reason: disposition.skipReason,
      block_loop: disposition.blockLoop,
      text: disposition.text,
      tokens,
      latency_ms: elapsed,
      status: aggregateStatus(results, skipped),
      toolchain,
    };
    return { disposition, row };
  };

  if (change.trigger === "command") {
    const disposition: Disposition = {
      ...base(),
      mechanism: "record",
      finalDisposition: "record",
      reviewStatus: "skipped",
      skipReason: "command_event",
    };
    skipped = true;
    skipReason = "command_event";
    return finish(disposition);
  }

  const files = change.files ?? [];
  if (files.length === 0) {
    const disposition: Disposition = {
      ...base(),
      mechanism: "record",
      finalDisposition: "record",
      reviewStatus: "skipped",
      skipReason: "no_supported_files",
    };
    skipped = true;
    skipReason = "no_supported_files";
    return finish(disposition);
  }

  const triageDeadline = clock.now() + ctx.config.budgets.crgQueryMs;
  const tierDecision = await decideTier(change, files, ctx, triageDeadline);
  const tier = tierDecision.tier;

  const semgrep = ctx.sources.find((source) => source.name === "semgrep");
  if (semgrep) {
    const decision = planCall(ledger, turn, costFor("semgrep", ctx.config), ctx.config.budgets.semgrepKillMs);
    if (!decision.start) {
      skipped = true;
      skipReason = decision.reason;
    } else {
      const started = clock.now();
      const result = await semgrep.review({
        event: change,
        tier,
        config: ctx.config,
        deadline: decision.deadline,
        sourceText,
      });
      ledger.charge(turn, clock.now() - started);
      results.push(result);
    }
  }

  const semgrepResult = results.find((result) => result.source === "semgrep");
  const semgrepFindings = semgrepResult && semgrepResult.status === "ok" ? semgrepResult.findings : [];
  const pSemgrep =
    semgrepFindings.length > 0
      ? Math.max(...semgrepFindings.map((finding) => singleSourceProbability(finding, ctx.config, ctx.artifact)))
      : null;

  let preDecision: Disposition["preDecision"] = semgrepResult ? "allow" : "not_run";
  let blockLoop = false;
  let denyFindings: Finding[] = [];

  if (pSemgrep !== null && pSemgrep >= ctx.config.thresholds.block) {
    const triggering = semgrepFindings.filter(
      (finding) => singleSourceProbability(finding, ctx.config, ctx.artifact) >= ctx.config.thresholds.block,
    );
    const keys = triggering.map((finding) => ({ file: finding.file, ruleId: ruleIdOf(finding) }));
    const verdict = guard.check(keys);
    if (verdict.deny) {
      preDecision = "deny";
      denyFindings = triggering;
    } else {
      blockLoop = verdict.blockLoop;
    }
  }

  const postSources = ctx.sources.filter((source) => source.name !== "semgrep");
  const runnable = postSources.filter((source) => !(source.name === "aor" && tier === 0));

  const postResults = await Promise.all(
    runnable.map(async (source) => {
      const cost = costFor(source.name, ctx.config);
      const decision = planCall(ledger, turn, cost, cost);
      if (!decision.start) {
        skipped = true;
        skipReason = skipReason ?? decision.reason;
        return null;
      }
      const started = clock.now();
      const result = await source.review({
        event: change,
        tier,
        config: ctx.config,
        deadline: decision.deadline,
        sourceText,
      });
      ledger.charge(turn, clock.now() - started);
      return result;
    }),
  );
  for (const result of postResults) {
    if (result) results.push(result);
  }

  const fused = fuse({ sources: results, config: ctx.config, artifact: ctx.artifact });
  const merged = fused.findings;
  mergedFindings = merged;

  let pFused: number | null;
  if (tier === 0) {
    const single = results.flatMap((result) => (result.status === "ok" ? result.findings : []));
    pFused =
      single.length > 0
        ? Math.max(...single.map((finding) => singleSourceProbability(finding, ctx.config, ctx.artifact)))
        : null;
  } else {
    pFused = fused.pFused;
  }

  let postDecision: Disposition["postDecision"] = postSources.length > 0 ? "none" : "not_run";
  let text: string | null = null;

  if (preDecision === "deny") {
    postDecision = "none";
    pFused = null;
    text = formatMessage(
      "[CRS-BLOCK]",
      merged.length > 0 ? merged : [],
    );
    if (merged.length === 0 && denyFindings.length > 0) {
      text = formatMessage(
        "[CRS-BLOCK]",
        denyFindings.map((finding) => ({
          ...finding,
          sources: [finding.source],
          rawIds: [finding.rawId],
          cweComparable: true,
          conflictResolution: "none",
          blockable: true,
        })),
      );
    }
  } else if (tier >= 1 && pFused !== null && pFused >= ctx.config.thresholds.warn) {
    const eligible = merged.filter((finding) => finding.blockable);
    if (eligible.length > 0) {
      postDecision = "inject_warn";
      text = formatMessage("[CRS-WARN]", eligible);
    }
  }

  const finalMechanism = mechanismOf(
    preDecision === "deny" ? "deny" : postDecision === "inject_warn" ? "inject_warn" : "none",
  );

  const disposition: Disposition = {
    mechanism: finalMechanism,
    findings: merged,
    text,
    pSemgrep,
    pFused,
    preDecision,
    postDecision,
    finalDisposition: finalMechanism,
    reviewStatus: reviewStatusOf(results, skipped, skipReason ?? tierDecision.skipReason),
    skipReason: skipReason ?? tierDecision.skipReason,
    blockLoop,
    tier,
    tierSource: tierDecision.tierSource,
    gate: { perFileTier: tierDecision.perFileTier },
  };

  return finish(disposition);
}
