import pLimit from "p-limit";
import type {
  CalibrationArtifact,
  ChangeEvent,
  Disposition,
  Finding,
  Instruments,
  MergedFinding,
  ReviewRow,
  ReviewSkipReason,
  ReviewStatus,
  RunConfig,
  SignalSource,
  SourceResult,
  Tier,
  Toolchain,
  TriageAnalysis,
  TriageProvider,
} from "../contracts/index.js";
import { configHash } from "../config/index.js";
import { fuse, singleSourceProbability } from "../l4/index.js";
import { TurnBudgetLedger, ledgerFor, planCall, systemClock, type Clock } from "./budget.js";
import type { ConclusionCache } from "./cache.js";
import { instrumentFor } from "./instruments.js";
import { formatMessage, groupKey, mechanismOf } from "./templates.js";
import { computeTier, staticTier, type TriageResult } from "./triage.js";

export interface DenyGroupKey {
  file: string;
  ruleId: string;
}

export class DenyGuard {
  private readonly counts = new Map<string, number>();

  check(keys: DenyGroupKey[]): { deny: boolean; blockLoop: boolean } {
    if (keys.length === 0) return { deny: false, blockLoop: false };
    const looping = keys.some((key) => (this.counts.get(groupKey(key)) ?? 0) >= 2);
    if (looping) return { deny: false, blockLoop: true };
    for (const key of keys) {
      this.counts.set(groupKey(key), (this.counts.get(groupKey(key)) ?? 0) + 1);
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
  /** Injected identity for tests; live runs observe the binaries themselves. */
  instrument?: Instruments;
  sourceText?: Record<string, string>;
  cache?: ConclusionCache | null;
}

export interface ReviewOutcome {
  disposition: Disposition;
  row: ReviewRow;
}

function ruleIdOf(finding: Finding): string {
  return finding.rawId.split("\u0000")[0] ?? finding.rawId;
}

export function defaultToolchain(config: RunConfig): Toolchain {
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
      return config.sources.aor.outerCapMs;
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
  if (
    skipReason === "index_not_ready" ||
    skipReason === "index_stale" ||
    skipReason === "budget_exhausted" ||
    skipReason === "turn_budget_exhausted" ||
    skipReason === "language_unsupported"
  ) {
    return "degraded";
  }
  return results.some((result) => result.status !== "ok") ? "degraded" : "ok";
}

type ThresholdKind = "block" | "warn";

/**
 * The sources' own severity scale: semgrep INFO/WARNING/ERROR map to 1/2/3 and
 * AOR P3/P2/P1 (or LOW/MEDIUM/HIGH) map to 1/2/3 as well. `>= 2` therefore
 * means "the source itself called this a warning or worse". That is a policy,
 * not a fitted parameter: it claims no calibrated probability, which is why it
 * can stand in when the artifact could not certify one.
 */
const WARN_SEVERITY = 2;

/**
 * A calibrated operating point, or the third state: the artifact exists but
 * could not certify one (`fit_negatives = 0`). `unfittable` is deliberately not
 * a number - substituting a constant here would be indistinguishable from a
 * fitted threshold.
 */
type Threshold = number | "unfittable";

function thresholdFor(ctx: ReviewContext, kind: ThresholdKind): (cwe: string | null) => Threshold {
  return (cwe) => {
    const perCategory = cwe ? ctx.artifact?.thresholds.perCategory[cwe] : undefined;
    const fitted = perCategory ? perCategory[kind] : null;
    if (fitted !== null && fitted !== undefined) return fitted;
    const global = ctx.artifact?.thresholds.global[kind];
    if (global !== null && global !== undefined) return global;
    // No artifact at all: calibration is off for this run, and the config's
    // declared threshold is the policy rather than a substitute for a fit.
    if (ctx.artifact === null) return ctx.config.thresholds[kind];
    return "unfittable";
  };
}

export async function review(change: ChangeEvent, ctx: ReviewContext): Promise<ReviewOutcome> {
  const clock = ctx.clock ?? systemClock;
  const ledger = ctx.ledger ?? ledgerFor(ctx.config, clock);
  const guard = ctx.guard ?? new DenyGuard();
  const toolchain = ctx.toolchain ?? defaultToolchain(ctx.config);
  // Observed once per process (cached inside `instrumentFor`): the row must name
  // the binary that answered, not the one the config asked for.
  const instrument = ctx.instrument ?? (await instrumentFor(ctx.config));
  const startedAt = clock.now();
  const turn = { sessionId: change.sessionId, rootCallId: change.rootCallId };
  const results: SourceResult[] = [];
  const sourceText = ctx.sourceText ?? {};
  let skipReason: ReviewSkipReason | null = null;
  let skipped = false;
  let mergedFindings: MergedFinding[] = [];
  // The tier decides whether AOR is asked at all (`runnable` below). Recorded on
  // the row so a 0-token row can be told apart from a lost measurement; a
  // consumer must never reconstruct it from `tokens === null` (ADR-0008).
  let aorInvoked = false;

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
    thresholdSource: null,
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
      threshold_source: disposition.thresholdSource,
      gate: disposition.gate,
      text: disposition.text,
      tokens,
      aor_invoked: aorInvoked,
      latency_ms: elapsed,
      status: aggregateStatus(results, skipped),
      toolchain,
      instrument,
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
  const callSource = async (
    source: SignalSource,
    ledger: TurnBudgetLedger,
  ): Promise<SourceResult | null> => {
    const cost = costFor(source.name, ctx.config);
    const key = ctx.cache ? ctx.cache.key(source.name, files, sourceText, tier) : null;
    if (key && ctx.cache) {
      const cached = ctx.cache.get(key);
      if (cached) return { ...cached, tokens: null, tokenDetail: null, latencyMs: 0 };
    }
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
    if (key && ctx.cache) ctx.cache.set(key, result);
    return result;
  };

  if (semgrep) {
    const result = await callSource(semgrep, ledger);
    if (result) results.push(result);
  }

  const semgrepResult = results.find((result) => result.source === "semgrep");
  const blockThreshold = thresholdFor(ctx, "block");
  const warnThreshold = thresholdFor(ctx, "warn");
  /**
   * How the warn operating point was obtained. A fitted threshold is a
   * probability claim and `severity_policy` is not, so the two are recorded as
   * different things rather than reported as one calibrated number.
   */
  const warnThresholdSource = (cwe: string | null): Disposition["thresholdSource"] => {
    if (ctx.artifact === null) return "config";
    return warnThreshold(cwe) === "unfittable" ? "severity_policy" : "artifact";
  };
  const probabilityOf = (finding: Finding): number =>
    singleSourceProbability(finding, ctx.config, ctx.artifact);
  const semgrepFindings = semgrepResult && semgrepResult.status === "ok" ? semgrepResult.findings : [];
  const pSemgrep =
    semgrepFindings.length > 0
      ? Math.max(...semgrepFindings.map(probabilityOf))
      : null;
  const triggering = semgrepFindings.filter((finding) => {
    if (finding.certified === false) return false;
    const threshold = blockThreshold(finding.cwe ?? null);
    // `unfittable` is not "a low threshold": the block face is gated by rule
    // certification, so a certified rule still blocks when no calibrated
    // probability threshold exists. Only the probability gate is dropped.
    return threshold === "unfittable" || probabilityOf(finding) >= threshold;
  });

  let preDecision: Disposition["preDecision"] = semgrepResult ? "allow" : "not_run";
  let blockLoop = false;
  let denyFindings: Finding[] = [];

  if (triggering.length > 0) {
    const keys = triggering.map((finding) => ({ file: finding.file, ruleId: ruleIdOf(finding) }));
    const verdict = guard.check(keys);
    if (verdict.deny) {
      preDecision = "deny";
      denyFindings = triggering;
    } else {
      blockLoop = verdict.blockLoop;
    }
  }

  const postSources = change.phase === "post" ? ctx.sources.filter((source) => source.name !== "semgrep") : [];
  const runnable = postSources.filter((source) => !(source.name === "aor" && tier === 0));
  // "Asked" means the source was in the phase's runnable set. A tier-0 row, a
  // pre row and a skipped row all record `false`; a row whose call was cancelled
  // by the budget records `true` with `tokens: null`, which is `na`, not 0.
  aorInvoked = runnable.some((source) => source.name === "aor");
  const semanticLedger = new TurnBudgetLedger(ctx.config.sources.aor.outerCapMs, clock);

  const limit = pLimit(
    Math.max(1, Math.min(ctx.config.budgets.maxConcurrency, Math.max(1, runnable.length))),
  );
  const postResults = await Promise.all(
    runnable.map((source) => limit(() => callSource(source, semanticLedger))),
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
  let warnByPolicy = false;

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
          evidenceSources: finding.evidence ? [finding.source] : [],
          certified: finding.certified !== false,
          cweComparable: true,
          conflictResolution: "none" as const,
          blockable: true,
        })),
      );
    }
  } else if (change.phase === "post" && pFused !== null) {
    const eligible: MergedFinding[] = [];
    for (const finding of merged) {
      if (finding.evidenceSources.length === 0) continue;
      const threshold = warnThreshold(finding.cwe ?? null);
      if (threshold === "unfittable") {
        // No fitted warn point: warn on the source's own declared severity.
        // This keeps the instruction-correction mechanism measurable without
        // pretending a probability was calibrated; the row carries
        // `threshold_source: severity_policy`.
        warnByPolicy = true;
        if (finding.severity >= WARN_SEVERITY) eligible.push(finding);
        continue;
      }
      if (finding.confidence >= threshold) eligible.push(finding);
    }
    if (eligible.length > 0) {
      postDecision = "inject_warn";
      text = formatMessage("[CRS-WARN]", eligible);
    }
  }

  const finalMechanism = mechanismOf(
    preDecision === "deny" ? "deny" : postDecision === "inject_warn" ? "inject_warn" : "none",
  );
  const deciding = merged[0];
  const thresholdSource: Disposition["thresholdSource"] = warnByPolicy
    ? "severity_policy"
    : warnThresholdSource(deciding?.cwe ?? null);

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
    thresholdSource,
    gate: { perFileTier: tierDecision.perFileTier },
  };

  return finish(disposition);
}
