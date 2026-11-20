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
  certified: z.boolean().optional(),
  rawId: z.string().min(1),
});
export type Finding = z.infer<typeof Finding>;

export const MergedFinding = Finding.extend({
  sources: z.array(SourceName).min(1),
  rawIds: z.array(z.string().min(1)).min(1),
  evidenceSources: z.array(SourceName),
  /** Which source contributed the merged severity; null when unknown. */
  severitySource: SourceName.nullable().optional(),
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

export const TokenDetail = z.object({
  total: z.number().int().nonnegative().nullable(),
  input: z.number().int().nonnegative().nullable(),
  output: z.number().int().nonnegative().nullable(),
  cacheRead: z.number().int().nonnegative().nullable(),
  cacheWrite: z.number().int().nonnegative().nullable(),
});
export type TokenDetail = z.infer<typeof TokenDetail>;

export const SourceResult = z.object({
  source: SourceName,
  status: SourceStatus,
  findings: z.array(Finding),
  coverage: Coverage,
  tokens: z.number().int().nonnegative().nullable(),
  tokenDetail: TokenDetail.nullable().optional(),
  latencyMs: z.number().nonnegative(),
  errorKind: z.string().nullable().optional(),
  synthetic: z.boolean().optional(),
});
export type SourceResult = z.infer<typeof SourceResult>;

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

export const DispositionMechanism = z.enum([
  "mechanical_block",
  "instruction_correction",
  "record",
]);
export type DispositionMechanism = z.infer<typeof DispositionMechanism>;

/**
 * How this row's operating point was obtained. `severity_policy` means the
 * artifact could not certify a warn threshold and the warning was triggered by
 * the sources' own declared severity instead - a policy, not a probability.
 */
export const ThresholdSource = z.enum(["artifact", "config", "severity_policy"]);
export type ThresholdSource = z.infer<typeof ThresholdSource>;

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
  /** null when the row never reached a decision (command/no-file events). */
  thresholdSource: ThresholdSource.nullable(),
  gate: z.object({ perFileTier: z.record(z.string(), Tier) }).optional(),
});
export type Disposition = z.infer<typeof Disposition>;

export const Budgets = z.object({
  callMs: z.number().int().positive(),
  turnMs: z.number().int().positive(),
  semgrepKillMs: z.number().int().positive(),
  crgQueryMs: z.number().int().positive(),
  fusionWriteMs: z.number().int().positive(),
  cacheTtlMs: z.number().int().positive(),
  maxConcurrency: z.number().int().positive(),
});
export type Budgets = z.infer<typeof Budgets>;

export const TierBoundary = z.object({
  filesMax: z.number().int().nonnegative(),
  nodesMax: z.number().int().nonnegative(),
});

export const SemgrepSourceConfig = z.object({
  enabled: z.boolean(),
  command: z.string().min(1),
  osemgrepCommand: z.string().min(1),
  version: z.string().min(1),
  fullBlockMaxBytes: z.number().int().positive(),
  subsets: z
    .array(
      z.object({
        id: z.string().min(1),
        path: z.string().min(1),
        sha256: z.string().min(1),
        langs: z.array(z.string().min(1)),
        blockRules: z.array(z.string().min(1)),
        nontaint: z.boolean().optional(),
      }),
    )
    .nonempty(),
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

/**
 * Identity of one measuring instrument, as the *measuring artefact* reports it.
 *
 * `toolchain` above is read from the config: it says what the run was supposed
 * to use. `Instrument` says what answered `--version` in the process that did
 * the measuring, which is the only thing a reader can reproduce against. The
 * two are recorded side by side so a drift shows up as a difference between
 * them instead of as a plausible row.
 *
 * `source` keeps the difference explicit: `observed` means a binary answered,
 * `declared` means the row never ran a live tool (replay) and only repeats the
 * config. Acceptance evaluation refuses anything that is not `observed`, so a
 * replay row cannot stand in for a live measurement.
 */
export const Instrument = z.object({
  name: z.string().min(1),
  version: z.string().min(1),
  commit: z.string().min(1).nullable(),
  source: z.enum(["observed", "declared"]),
});
export type Instrument = z.infer<typeof Instrument>;

/**
 * The model behind AOR, which is the instrument `ocr` the binary points at.
 *
 * Pinning `ocr` by commit says which client asked the question; it says nothing
 * about the model that answered. That model is configurable, and a service can
 * change it under a fixed id, so the row records the answer rather than the
 * request:
 *
 * - `id` is the model the service reported for this process (`deepseek-flash`
 *   answers a request for `deepseek-chat`). It is the ruler: it wrote the
 *   findings.
 * - `params.configured` is what the client asked for, read from ocr's own
 *   config. Kept beside the answer so an alias is visible instead of being
 *   guessed at, and so a config change mid-run shows up as a difference.
 * - `params.url` is the endpoint the answer came from.
 *
 * If a build ever compiles the model in, the honest value is still a statement:
 * `bundled@<commit>`. "Fixed" has to be recorded too, or the field goes empty
 * and nobody can tell a fixed model from an unrecorded one.
 */
export const AorModel = z.object({
  provider: z.string().min(1),
  id: z.string().min(1),
  params: z.object({
    url: z.string().min(1).nullable(),
    configured: z.string().min(1).nullable(),
  }),
  source: z.enum(["observed", "declared"]),
});
export type AorModel = z.infer<typeof AorModel>;

/** The instruments a live acceptance run must identify, deepest last. */
export const Instruments = z.object({
  semgrep: Instrument,
  ocr: Instrument,
  aor_model: AorModel,
});
export type Instruments = z.infer<typeof Instruments>;

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
  threshold_source: ThresholdSource.nullable(),
  gate: z.object({ perFileTier: z.record(z.string(), Tier) }).optional(),
  text: z.string().nullable(),
  tokens: z.number().int().nonnegative().nullable(),
  /**
   * Was a semantic pass (AOR) asked of this row at all?
   *
   * `tokens: null` says "no number", not why: a tier-0 row never calls AOR, so
   * its cost is 0 by construction, while a tier-2 row whose call timed out has a
   * cost that is unknown. Consumers read this field instead of inferring the
   * call from a null token count (ADR-0008: an unmeasured value is not a 0).
   */
  aor_invoked: z.boolean(),
  latency_ms: z.number().nonnegative(),
  status: z.enum(["ok", "partial", "timeout", "failed", "unknown", "skipped"]),
  toolchain: Toolchain,
  /** What actually answered `--version`; see `Instrument`. */
  instrument: Instruments,
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
  /**
   * Whether the write creates the file or edits one that already exists.
   * Derived from `before === ""`; never filled in by hand. A dataset that only
   * ever edits cannot exercise the create path, so the split is reported.
   */
  event_kind: z.enum(["edit", "create"]),
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

/**
 * A calibration category is `CWE-<n>`, unpadded — the spelling findings already
 * use (`src/l3/semgrep.ts` normalises to `CWE-22`, and `sample_cwe` is
 * `/^CWE-\d+$/`). `CWE-022`, `022` and `CWE-22: Improper ...` all land on `CWE-22`.
 */
export function cweCategory(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined) return null;
  const text = String(raw).trim();
  const labelled = /CWE-(\d{1,4})/i.exec(text);
  const digits = labelled?.[1] ?? (/^\d{1,4}$/.test(text) ? text : undefined);
  return digits === undefined ? null : `CWE-${Number(digits)}`;
}

/**
 * The classes calibration is allowed to fit, derived rather than listed.
 *
 * #7 D2: `categories = (数据集 manifest 的 sample_cwe 集合) ∩ (规则表声明的 CWE 集合)`.
 * The old hand-written list (`CWE-502` present, `CWE-918` missing, wrong order)
 * silently kept a `CWE-502: n=15` grid alive after the classes changed, and a
 * calibration artifact that names a class the dataset no longer has is worse
 * than no artifact: it applies a threshold nobody fitted.
 */
export function calibrationCategories(
  datasetCwes: Iterable<string | null | undefined>,
  rulesetCwes: Iterable<string | null | undefined>,
): string[] {
  const declared = new Set<string>();
  for (const raw of rulesetCwes) {
    const key = cweCategory(raw);
    if (key !== null) declared.add(key);
  }
  const out = new Set<string>();
  for (const raw of datasetCwes) {
    const key = cweCategory(raw);
    if (key !== null && declared.has(key)) out.add(key);
  }
  return [...out].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

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
  /** Which dataset version these thresholds were fitted on. */
  dataset_version: z.string().min(1),
  /** sha256 of the coverage source (`rules_table.json`) that declares the classes. */
  ruleset_fingerprint: z.string().min(1),
  /** `calibrationCategories(dataset, ruleset)` at fit time, sorted. */
  categories: z.array(z.string().min(1)),
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
    /**
     * `unfittable` means no operating point exists. It is a state, not a low
     * threshold: a consumer must propagate it and must never substitute a
     * constant (0.5, 0.7, or the config's declared value).
     */
    status: z.enum(["fitted", "unfittable"]).optional(),
    /**
     * Why the fit failed, recorded separately for each cause: `fit_negatives`
     * is a design choice (precision is measured once, in eval), the other two
     * are corpus size. Collapsing them into one `insufficient_support` hides
     * which cause a fix would have to attack.
     */
    causes: z
      .object({
        /** Fit rows with no defect: PAVA needs both classes, or it degenerates. */
        fit_negatives: z.number().int().nonnegative(),
        /** Largest number of findings one class contributed (the 30-gate counts these). */
        class_declarations: z.number().int().nonnegative(),
        /** Rules the pinned ruleset declares for that same class. */
        class_rules: z.number().int().nonnegative(),
        /** Findings the fit run produced. */
        n_fit: z.number().int().nonnegative(),
      })
      .optional(),
  }),
  synthetic: z.boolean().optional(),
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
