import { z } from "zod";

export const PHASES = ["pre", "post", "disposition"] as const;
export const TRIGGERS = ["write", "edit", "command"] as const;
export const DIFF_PROVENANCE = ["synthesized", "observed", "none"] as const;
export const SOURCE_NAMES = ["semgrep", "aor", "crg", "registry"] as const;
export const SOURCE_STATUS = ["ok", "timeout", "error", "degraded"] as const;
export const REVIEW_STATUS = ["ok", "degraded", "skipped"] as const;
export const TIERS = [0, 1, 2] as const;
export const BASELINES = ["B0", "B1", "B2", "B3", "B4g", "B4", "single"] as const;
export const MODES = ["replay", "live"] as const;

export const REVIEW_SKIP_REASONS = [
  "no_supported_files",
  "language_unsupported",
  "resource_limit",
  "turn_budget_exhausted",
  "budget_exhausted",
  "index_not_ready",
  "index_stale",
  "aor_timeout",
  "aor_partial",
  "no_evidence",
  "tier0_no_semantic",
  "duplicate_reuse",
  "no_change",
  "command_event",
  "disposition_missing",
] as const;

export const Phase = z.enum(PHASES);
export const Trigger = z.enum(TRIGGERS);
export const DiffProvenance = z.enum(DIFF_PROVENANCE);
export const SourceName = z.enum(SOURCE_NAMES);
export const SourceStatus = z.enum(SOURCE_STATUS);
export const ReviewStatus = z.enum(REVIEW_STATUS);
export const ReviewSkipReason = z.enum(REVIEW_SKIP_REASONS);
export const Tier = z.union([z.literal(0), z.literal(1), z.literal(2)]);
export const Baseline = z.enum(BASELINES);
export const Mode = z.enum(MODES);

export type Tier = z.infer<typeof Tier>;
export type Baseline = z.infer<typeof Baseline>;
export type Mode = z.infer<typeof Mode>;
export type Phase = z.infer<typeof Phase>;
export type Trigger = z.infer<typeof Trigger>;
export type DiffProvenance = z.infer<typeof DiffProvenance>;
export type SourceName = z.infer<typeof SourceName>;
export type SourceStatus = z.infer<typeof SourceStatus>;
export type ReviewStatus = z.infer<typeof ReviewStatus>;
export type ReviewSkipReason = z.infer<typeof ReviewSkipReason>;
export type DispositionMechanismValue = DispositionMechanism;

export const ChangeEvent = z.object({
  id: z.string().min(1),
  sessionId: z.string().min(1),
  rootCallId: z.string().min(1),
  phase: Phase,
  trigger: Trigger,
  files: z.array(z.string().min(1)).nullable(),
  diff: z.string().nullable(),
  diffProvenance: DiffProvenance,
  ts: z.number().int().nonnegative(),
});
export type ChangeEvent = z.infer<typeof ChangeEvent>;

export const Finding = z.object({
  file: z.string().min(1),
  startLine: z.number().int().nonnegative(),
  endLine: z.number().int().nonnegative(),
  symbol: z.string().nullable().optional(),
  severity: z.number(),
  confidence: z.number().min(0).max(1),
  source: SourceName,
  cwe: z.string().regex(/^CWE-\d+$/).nullable().optional(),
  evidence: z.string().nullable().optional(),
  rawId: z.string().min(1),
});
export type Finding = z.infer<typeof Finding>;

export const MergedFinding = Finding.extend({
  sources: z.array(SourceName).min(1),
  rawIds: z.array(z.string().min(1)).min(1),
  cweComparable: z.boolean(),
  conflictResolution: z.enum(["none", "evidence_preferred", "vote", "downgraded"]),
  blockable: z.boolean(),
});
export type MergedFinding = z.infer<typeof MergedFinding>;

export const Coverage = z.object({
  filesCovered: z.number().int().nonnegative(),
  filesUnknown: z.number().int().nonnegative(),
});
export type Coverage = z.infer<typeof Coverage>;

export const SourceResult = z.object({
  source: SourceName,
  status: SourceStatus,
  findings: z.array(Finding),
  coverage: Coverage,
  tokens: z.number().int().nonnegative().nullable(),
  latencyMs: z.number().nonnegative(),
  errorKind: z.string().nullable().optional(),
});
export type SourceResult = z.infer<typeof SourceResult>;

export const DispositionMechanism = z.enum([
  "mechanical_block",
  "instruction_correction",
  "record",
]);
export type DispositionMechanism = z.infer<typeof DispositionMechanism>;

export const Disposition = z.object({
  mechanism: DispositionMechanism,
  findings: z.array(MergedFinding),
  text: z.string().nullable(),
  pSemgrep: z.number().nullable(),
  pFused: z.number().nullable(),
  preDecision: z.enum(["deny", "allow", "not_run"]),
  postDecision: z.enum(["inject_warn", "none", "not_run"]),
  finalDisposition: DispositionMechanism,
  reviewStatus: ReviewStatus,
  skipReason: ReviewSkipReason.nullable(),
  blockLoop: z.boolean(),
  tier: Tier,
  tierSource: z.enum(["triage", "static", "none"]),
  gate: z.object({ perFileTier: z.record(z.string(), Tier) }).optional(),
});
export type Disposition = z.infer<typeof Disposition>;

export const Budgets = z.object({
  callMs: z.number().int().positive(),
  turnMs: z.number().int().positive(),
  semgrepKillMs: z.number().int().positive(),
  crgQueryMs: z.number().int().positive(),
  fusionWriteMs: z.number().int().positive(),
  softCapMs: z.number().int().positive(),
});
export type Budgets = z.infer<typeof Budgets>;

export const TierBoundary = z.object({
  filesMax: z.number().int().nonnegative(),
  nodesMax: z.number().int().nonnegative(),
});

export const SemgrepSourceConfig = z.object({
  enabled: z.boolean(),
  command: z.string().min(1),
  version: z.string().min(1),
  rulesPath: z.string().min(1),
  rulesSha256: z.string().min(1),
  subsets: z
    .array(
      z.object({
        id: z.string().min(1),
        path: z.string().min(1),
        sha256: z.string().min(1),
        langs: z.array(z.string().min(1)),
        blockRules: z.array(z.string().min(1)),
      }),
    )
    .nonempty(),
  timeoutsMs: z.object({ callMs: z.number().int().positive() }),
  failOpenOverBytes: z.record(z.string(), z.number().int().positive()),
});

export const AorSourceConfig = z.object({
  enabled: z.boolean(),
  command: z.string().min(1),
  versionCommit: z.string().min(1),
  outerCapMs: z.number().int().positive(),
  concurrency: z.number().int().positive(),
  timeoutPerFileMs: z.number().int().positive(),
  maxChunks: z.number().int().positive(),
  preview: z.object({
    enabled: z.boolean(),
    budgetSwitchRatio: z.number().positive(),
  }),
  tierTokens: z.object({ tier1: z.number().int().positive(), tier2: z.number().int().positive() }),
  tier2MaxTools: z.number().int().positive(),
});

export const CrgSourceConfig = z.object({
  enabled: z.boolean(),
  command: z.string().min(1),
  indexTimeoutMs: z.number().int().positive(),
});

export const RegistrySourceConfig = z.object({
  enabled: z.boolean(),
  command: z.string().min(1),
  timeoutMs: z.number().int().positive(),
});

export const RunConfig = z.object({
  version: z.string().min(1),
  mode: Mode,
  baseline: Baseline,
  sources: z.object({
    semgrep: SemgrepSourceConfig,
    aor: AorSourceConfig,
    crg: CrgSourceConfig,
    registry: RegistrySourceConfig,
  }),
  fusionStages: z.object({
    merge: z.boolean(),
    conflict: z.boolean(),
    calibrate: z.boolean(),
    vote: z.boolean(),
  }),
  tieBreak: z.enum(["max", "first"]),
  triage: z.object({
    enabled: z.boolean(),
    tier0: TierBoundary,
    tier1: TierBoundary,
  }),
  budgets: Budgets,
  thresholds: z.object({ block: z.number().min(0).max(1), warn: z.number().min(0).max(1) }),
  weights: z.object({ single: z.number().positive(), dual: z.number().positive() }),
  prior: z.object({ pPrior: z.number().gt(0).lt(1) }),
  calibration: z.object({ artifactPath: z.string().min(1), version: z.string().min(1) }),
  sMax: z.record(z.string(), z.number().int().positive()),
  persistence: z.object({
    jsonlPath: z.string().min(1),
    rawDir: z.string().min(1),
    turnStatePath: z.string().min(1),
  }),
});
export type RunConfig = z.infer<typeof RunConfig>;
export type SemgrepSourceConfig = z.infer<typeof SemgrepSourceConfig>;
export type AorSourceConfig = z.infer<typeof AorSourceConfig>;
export type CrgSourceConfig = z.infer<typeof CrgSourceConfig>;
export type RegistrySourceConfig = z.infer<typeof RegistrySourceConfig>;

export const Toolchain = z.object({
  semgrep: z.string(),
  aor: z.string(),
  crg: z.string(),
  node: z.string(),
  platform: z.string(),
});
export type Toolchain = z.infer<typeof Toolchain>;

export const ReviewRow = z.object({
  run_id: z.string().min(1),
  config_hash: z.string().min(1),
  baseline: Baseline,
  mode: Mode,
  change_event: ChangeEvent,
  tier: Tier,
  tier_source: z.enum(["triage", "static", "none"]),
  sources: z.array(SourceResult),
  findings_merged: z.array(MergedFinding),
  p_semgrep: z.number().nullable(),
  p_fused: z.number().nullable(),
  pre_decision: z.enum(["deny", "allow", "not_run"]),
  post_decision: z.enum(["inject_warn", "none", "not_run"]),
  final_disposition: DispositionMechanism,
  review_status: ReviewStatus,
  review_skip_reason: ReviewSkipReason.nullable(),
  block_loop: z.boolean(),
  gate: z.object({ perFileTier: z.record(z.string(), Tier) }).optional(),
  text: z.string().nullable(),
  tokens: z.number().int().nonnegative().nullable(),
  latency_ms: z.number().nonnegative(),
  status: z.enum(["ok", "partial", "timeout", "failed", "unknown", "skipped"]),
  toolchain: Toolchain,
});
export type ReviewRow = z.infer<typeof ReviewRow>;

export const RunRecord = z.object({
  run_id: z.string().min(1),
  sample: z.string().min(1),
  tier: Tier,
  repeat: z.number().int().nonnegative(),
  mode: Mode,
  baseline: Baseline,
  config_hash: z.string().min(1),
  change_event: ChangeEvent.nullable(),
  findings_merged: z.array(MergedFinding),
  findings_raw_ref: z.string().min(1),
  sources: z.array(SourceResult),
  disposition: Disposition,
  gate: z.object({ perFileTier: z.record(z.string(), Tier) }).optional(),
  tokens: z.object({
    total: z.number().int().nonnegative().nullable(),
    input: z.number().int().nonnegative().nullable(),
    output: z.number().int().nonnegative().nullable(),
    cache_read: z.number().int().nonnegative().nullable(),
    cache_write: z.number().int().nonnegative().nullable(),
  }),
  latency_ms: z.number().nonnegative(),
  status: z.enum(["ok", "partial", "timeout", "failed", "unknown", "skipped"]),
  outcome: z.enum(["block", "warn", "record", "none"]),
  error: z.string().nullable(),
  toolchain: Toolchain,
  repo: z.object({ rev: z.string().min(1), files_scanned: z.number().int().nonnegative() }),
  cache: z.enum(["cold", "warm"]).nullable(),
});
export type RunRecord = z.infer<typeof RunRecord>;

export const PairingRow = z.object({
  run_id: z.string().min(1),
  gt_id: z.string().min(1),
  merged_id: z.string().nullable(),
  overlap: z.number().int().nonnegative(),
  union: z.number().int().nonnegative(),
});
export type PairingRow = z.infer<typeof PairingRow>;

export const AnnotationSample = z.object({
  sample_id: z.string().min(1),
  group_id: z.string().min(1),
  split: z.enum(["fit", "eval"]),
  cwe: z.string().regex(/^CWE-\d+$/).nullable(),
  risk_level: z.enum(["low", "medium", "high"]),
  paired_safe: z.boolean(),
  language: z.string().min(1),
  path: z.string().min(1),
  changed_lines: z.number().int().nonnegative(),
  content_sha256: z.string().min(1),
  expected_detectable_by: z.array(SourceName),
});
export type AnnotationSample = z.infer<typeof AnnotationSample>;

export const DatasetManifest = z.object({
  version: z.string().min(1),
  content_sha256_root: z.string().min(1),
  samples: z.array(AnnotationSample),
});
export type DatasetManifest = z.infer<typeof DatasetManifest>;

export const CALIBRATION_CATEGORIES = [
  "CWE-78",
  "CWE-79",
  "CWE-89",
  "CWE-94",
  "CWE-22",
  "CWE-502",
  "CWE-798",
] as const;

export const CalibrationGrid = z.object({
  source: SourceName,
  category: z.string(),
  n: z.number().int().nonnegative(),
  points: z.array(
    z.object({
      rawLow: z.number(),
      rawHigh: z.number(),
      p: z.number().min(0).max(1),
    }),
  ),
});
export type CalibrationGrid = z.infer<typeof CalibrationGrid>;

export const CalibrationArtifact = z.object({
  version: z.string().min(1),
  pPrior: z.number().gt(0).lt(1),
  shrinkageN0: z.number().positive(),
  pMax: z.number().gt(0).lte(1),
  fitRoot: z.string().min(1),
  grids: z.array(CalibrationGrid),
  thresholds: z.object({
    global: z.object({
      block: z.number().min(0).max(1).nullable(),
      warn: z.number().min(0).max(1).nullable(),
    }),
    perCategory: z.record(
      z.string(),
      z.object({ block: z.number().min(0).max(1).nullable(), warn: z.number().min(0).max(1).nullable() }),
    ),
    skipped: z.array(z.object({ scope: z.string(), reason: z.string() })),
  }),
});
export type CalibrationArtifact = z.infer<typeof CalibrationArtifact>;

export interface SignalSource {
  readonly name: z.infer<typeof SourceName>;
  review(input: SourceReviewInput): Promise<SourceResult>;
}

export interface SourceReviewInput {
  event: ChangeEvent;
  tier: Tier;
  config: RunConfig;
  deadline: number;
  sourceText: Record<string, string>;
}

export interface FusionStage {
  readonly name: "merge" | "conflict" | "calibrate" | "vote";
  apply(ctx: FusionContext): FusionContext | Promise<FusionContext>;
}

export interface FusionContext {
  findings: MergedFinding[];
  sources: SourceResult[];
  config: RunConfig;
  artifact: CalibrationArtifact | null;
}

export const CONTRACT_SCHEMAS = {
  ChangeEvent,
  Finding,
  MergedFinding,
  SourceResult,
  Disposition,
  RunConfig,
  ReviewRow,
  RunRecord,
  PairingRow,
  AnnotationSample,
  DatasetManifest,
  CalibrationArtifact,
} as const;
