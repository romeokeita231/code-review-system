import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AorModel, Instruments, ReviewRow, RunRecord } from "../src/contracts/index.js";
import { loadDataset } from "../src/l5/replay.js";
import { coverageCounts, cweKey, declaredCoverage, loadRulesTable, semgrepLanguage } from "./coverage.js";
import { arg } from "./shared.js";

export interface LabelSpan {
  path: string;
  startLine: number;
  endLine: number;
  cwe: string | null;
}

export interface SampleTruth {
  sample_id: string;
  split: string;
  risk_level: string;
  paired_safe: boolean;
  /** Needed to decide whether any shipped subset could scan this row. */
  language: string;
  /** `create` or `edit`; derived from `before === ""`, never filled by hand. */
  event_kind?: string;
  /** Ground-truth class; decides whether the pinned ruleset can see it at all. */
  sample_cwe: string | null;
  labels: LabelSpan[];
  expected_detectable_by: string[];
  /** The dataset's `after` body; line 3 extracts the GT text from it by label span. */
  after: string;
}

/** The identity line 3 uses for one independent run of one sample. */
export function line3PairKey(baseline: string, sample: string): string {
  return `${baseline}\u0000${sample}`;
}

/**
 * Declared rule coverage per CWE, from the frozen rules table. A class present
 * with 0 rules is a ruleset hole, not a sample defect: its samples stay out of
 * the recall denominator and get their own row in the results table.
 */
export interface RuleCoverage {
  language: string;
  perCwe: Record<string, number>;
}

/**
 * What the staged rows would be in the pinned upstream checkout, where this
 * project wrote none of the importers.
 *
 * Line 4 divides two token counts measured on a tree the drill assembled: each
 * staged file has three one-line importers, and those importers are what put it
 * above the tier boundary. The ratio therefore answers "does the ladder save
 * tokens when the radius is below the boundary", not "does it save tokens on this
 * corpus" - on the pinned repositories 0 of the 18 measurable rows is tier 0
 * (smallest file: 3 importers, boundary: 3). That counterfactual is measured once
 * by `scripts/upstream-context.ts` and frozen in `artifacts/staged-context.json`;
 * it belongs in line 4's `detail` so the ratio cannot be quoted without it.
 */
export interface Tier0Counterfactual {
  /** The defect-free rows line 4 pairs: how many had an upstream counterpart. */
  pairs_measured: number;
  pairs_tier0: number;
  /** Every staged row with an upstream counterpart, ten positives included. */
  rows_measured: number;
  rows_tier0: number;
  min_importers: number | null;
  files_max: number;
  source: string;
}

interface StagedContextRow {
  upstream_applicable?: boolean;
  upstream_importers?: number | null;
  would_be_tier?: number | null;
}

interface StagedContextFile {
  bounds?: { tier0_filesMax?: number };
  rows?: StagedContextRow[];
  summary?: {
    positives_upstream_tier0?: number;
    negatives_upstream_tier0?: number;
    negatives_upstream_tier_ge1?: number;
    measured_positives?: number;
  };
}

/**
 * Read the counterfactual, refusing a file whose rows and summary disagree.
 *
 * A missing artefact is `undefined` (the detail says the measurement was never
 * taken); a malformed one throws, because "0 of 0" is exactly the shape a
 * degraded measurement has and this project has already paid for reading that as
 * a fact four times.
 */
export function tier0Counterfactual(path: string): Tier0Counterfactual {
  const raw = JSON.parse(readFileSync(path, "utf8")) as StagedContextFile;
  const summary = raw.summary;
  const filesMax = raw.bounds?.tier0_filesMax;
  if (summary === undefined || filesMax === undefined || !Array.isArray(raw.rows)) {
    throw new Error(
      `${path} is not a staged-context artefact: bounds.tier0_filesMax, summary and rows are required`,
    );
  }
  const posTier0 = summary.positives_upstream_tier0 ?? 0;
  const negTier0 = summary.negatives_upstream_tier0 ?? 0;
  const negAbove = summary.negatives_upstream_tier_ge1 ?? 0;
  const measuredPos = summary.measured_positives ?? 0;
  const measurable = raw.rows.filter((entry) => entry.upstream_applicable === true);
  const counted = measurable.filter((entry) => entry.would_be_tier === 0).length;
  if (counted !== posTier0 + negTier0 || measurable.length !== measuredPos + posTier0 + negTier0 + negAbove) {
    throw new Error(
      `${path} contradicts itself: ${measurable.length} measurable rows (${counted} at tier 0) against ` +
        `summary ${measuredPos + posTier0 + negTier0 + negAbove} rows (${posTier0 + negTier0} at tier 0)`,
    );
  }
  const importers = measurable
    .map((entry) => entry.upstream_importers)
    .filter((value): value is number => typeof value === "number");
  return {
    pairs_measured: negTier0 + negAbove,
    pairs_tier0: negTier0,
    rows_measured: measurable.length,
    rows_tier0: posTier0 + negTier0,
    min_importers: importers.length === 0 ? null : Math.min(...importers),
    files_max: filesMax,
    source: path,
  };
}

/**
 * The pinned config's block-certification face: per ruleset subset, its
 * languages and the rule ids it may deny on.
 *
 * `semgrep.ts:493` marks a finding `certified` only when its id is in
 * `blockRules`, and `orchestrator.ts:385` drops every finding that is not
 * certified, so a language whose subsets list no rule has no reachable `deny`.
 * That is why line 1 prints the certification face next to recall instead of
 * letting the number 0 pass as "missed every sample": the 0 is a fact about the
 * config wearing the detector's clothes.
 *
 * An empty block face is nevertheless a **failed line**, not `na` (D13: "`block`
 * 档为空则本线不通过", with the pre-registered conclusion sentence). `na` leaves
 * the gate denominator; that would turn "this dataset has no blocking capability
 * at the required precision" into "this line was never measured", which is a
 * different claim and a softer one.
 *
 * Read from the pinned file rather than from the run: `blockRules` is wiring, not
 * a goalpost, and the run records only the config hash.
 */
export function certifiedSubsets(path: string): Array<{ langs: string[]; blockRules: string[] }> {
  const raw = JSON.parse(readFileSync(path, "utf8")) as {
    sources?: { semgrep?: { subsets?: Array<{ langs?: unknown; blockRules?: unknown }> } };
  };
  const subsets = raw.sources?.semgrep?.subsets;
  if (!Array.isArray(subsets)) {
    throw new Error(`${path} declares no sources.semgrep.subsets: cannot tell which rules may block`);
  }
  return subsets.map((subset) => ({
    langs: Array.isArray(subset.langs) ? subset.langs.map(String) : [],
    blockRules: Array.isArray(subset.blockRules) ? subset.blockRules.map(String) : [],
  }));
}

export interface AcceptanceOptions {
  minSamples?: number;
  /** Precision's gate counts findings, not samples; a separate unit needs its own n. */
  minFindings?: number;
  /** Absent means "coverage unknown" - then every labelled eval sample counts. */
  coverage?: RuleCoverage;
  /**
   * What line 4's population would be in the pinned repositories. Absent means
   * the counterfactual was never measured, which the detail says in words rather
   * than defaulting to zero.
   */
  stagedContext?: Tier0Counterfactual;
  /**
   * Who produced the rows. Absent means the caller did not say, and line 4 then
   * prints `source=unknown` rather than claiming a measurement: a synthetic
   * fixture's 1000/1100 renders as `0.909`, identical in shape to a measured
   * ratio, so the origin has to be stated rather than inferred (ADR-0008).
   */
  rowsSource?: "live" | "synthetic";
  /**
   * What the five numbers are allowed to have been produced on. When given, a
   * mismatch refuses the report instead of warning about it: the failure mode
   * this guards is a complete-looking artefact built on a different binary.
   */
  frozenInstruments?: FrozenInstruments;
  /**
   * The config's block-certification face: per ruleset subset, its languages and
   * the rule ids it may deny on. `semgrep.ts:493` marks a finding `certified`
   * only when its id is listed there, and `orchestrator.ts:385` drops every
   * uncertified finding, so a subset with `blockRules: []` makes `deny`
   * unreachable for its language. Recall is then `na`, not 0: nothing was
   * attempted that could have succeeded, and calling that a miss would report
   * the ruleset's hole as the detector's blindness. Absent means the caller did
   * not say, and the line is gated the way it always was.
   */
  subsets?: ReadonlyArray<{ langs: readonly string[]; blockRules: readonly string[] }>;
  /**
   * The final body of each staged file, keyed by `line3PairKey(baseline, sample)`.
   * `null` (or an absent key) is a missing snapshot, never an empty file. When
   * the whole map is absent the run carries no snapshot and line 3 keeps the
   * detection-only reading instead of calling every pair `not_measured`.
   */
  finalContent?: ReadonlyMap<string, string | null>;
}

export type { FrozenInstruments } from "./frozen.js";
import { loadFrozenPin } from "./frozen.js";
import type { FrozenInstruments } from "./frozen.js";

/** Wilson score interval for `k` successes in `n` trials; `null` when `n = 0`. */
export function wilsonInterval(
  k: number,
  n: number,
  z = 1.96,
): { low: number; high: number } | null {
  if (n <= 0) return null;
  const p = k / n;
  const denominator = 1 + (z * z) / n;
  const centre = p + (z * z) / (2 * n);
  const spread = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return {
    low: Math.max(0, (centre - spread) / denominator),
    high: Math.min(1, (centre + spread) / denominator),
  };
}

export interface BlockGaps {
  preregistered_at: string;
  gaps: Array<{ sample_id: string; reason: string }>;
}

export interface AcceptanceRowLike {
  sample: string;
  baseline: string;
  mode: string;
  disposition: {
    preDecision: "deny" | "allow" | "not_run";
    postDecision: "inject_warn" | "none" | "not_run";
    finalDisposition: string;
    text: string | null;
  };
  findings_merged: Array<{ file: string; startLine: number; endLine: number; cwe: string | null }>;
  sources: Array<{
    source: string;
    status: string;
    /** `language_unsupported` = never attempted, not a failed attempt. */
    errorKind?: string | null;
    findings: Array<{ file: string; cwe: string | null; evidence: string | null }>;
  }>;
  tokens: { total: number | null } | number | null;
  latency_ms: number;
  change_event: { sessionId: string; ts: number; phase?: string } | null;
  /**
   * Why the pipeline skipped the review, when it did. `language_unsupported`
   * means the source was never attempted, which is a different fact from a
   * timeout (attempted, failed) and must not share its denominator.
   */
  review_skip_reason?: string | null;
  /**
   * The tier the row was reviewed at. Carried so `evaluate` can refuse a run in
   * which a positive row silently fell back to the static ladder: that row never
   * reached AOR, and its absence from the contingency table looks like a
   * detection failure rather than a missing measurement.
   */
  tier?: number;
  tier_source?: string;
  /**
   * Did AOR review this row at all? A positive that fell to tier 0 keeps its
   * semgrep findings and its block decision, but has no correction and no anchor
   * - so it stays in the block denominators and leaves AOR's. Absent means
   * "no reason to think otherwise", which is what a replay row is.
   */
  aor_participated?: boolean;
  /**
   * Did a semantic pass run for this row? Written by the orchestrator where the
   * tier is decided: `false` means AOR was never asked, so a cost of 0 is a fact
   * about the ladder and not a missing measurement. Legacy rows carry `tier: 0`
   * + `tier_source: "triage"` instead, which is the same decision; `tokens ===
   * null` is never used to infer this either way.
   */
  aor_invoked?: boolean;
  /**
   * What answered `--version` when this row was produced. Required for any
   * report that quotes a number; `assertInstrumentIdentity` refuses without it.
   */
  instrument?: Instruments;
}

function sameCommit(a: string, b: string): boolean {
  return a.startsWith(b) || b.startsWith(a);
}

/**
 * Refuse to report on a run whose tools are not the frozen ones.
 *
 * This is an error, not a warning, because the failure it prevents is an
 * artefact that looks finished: the drift from `04deca6` to `4236c87` produced
 * valid rows and a complete report, and only the pin check noticed. The check
 * has to sit in front of the numbers, not beside them.
 */
export function assertInstrumentIdentity(
  rows: readonly AcceptanceRowLike[],
  frozen: FrozenInstruments,
  /** The graph CLI as it runs now; omitted by callers that cannot observe it. */
  currentCrg?: { version: string },
): Instruments {
  const problems: string[] = [];
  if (rows.length === 0) problems.push("no rows to evaluate");
  // CRG draws the tier boundary but does not stamp rows, so its drift is a
  // run-level fact: compare the pin with the installed binary, not with a row.
  // A pin without `crg` is an old run - incomplete, not drifted.
  if (frozen.crg !== undefined && currentCrg !== undefined && frozen.crg.version !== currentCrg.version) {
    problems.push(
      `crg version ${frozen.crg.version} != current ${currentCrg.version} - tier was drawn by a different graph CLI than the pin names`,
    );
  }
  const missing = rows.filter((row) => row.instrument === undefined).length;
  if (missing > 0) problems.push(`${missing} row(s) carry no instrument identity`);

  const seen = new Map<string, Instruments>();
  for (const row of rows) {
    if (row.instrument === undefined) continue;
    const model = row.instrument.aor_model;
    const key =
      `${row.instrument.semgrep.name}@${row.instrument.semgrep.version}` +
      `|${row.instrument.ocr.name}@${row.instrument.ocr.version}(${row.instrument.ocr.commit ?? "none"})` +
      `|${model?.provider}/${model?.id ?? "none"}@${model?.params.url ?? "none"}`;
    seen.set(key, row.instrument);
  }
  if (seen.size > 1) problems.push(`rows were produced on ${seen.size} different instruments: ${[...seen.keys()].join(", ")}`);
  for (const [key, instrument] of seen) {
    if (instrument.semgrep.source !== "observed" || instrument.ocr.source !== "observed") {
      problems.push(`${key}: instrument identity is declared from config, not observed`);
    }
    if (instrument.semgrep.version !== frozen.semgrep.version) {
      problems.push(
        `${key}: semgrep ${instrument.semgrep.version} != frozen ${frozen.semgrep.version}`,
      );
    }
    if (instrument.ocr.commit === null || !sameCommit(instrument.ocr.commit, frozen.ocr.commit)) {
      problems.push(
        `${key}: ocr commit ${instrument.ocr.commit ?? "none"} != frozen ${frozen.ocr.commit}`,
      );
    }
    problems.push(...aorModelProblems(instrument.aor_model, frozen.aor_model, key));
  }
  if (problems.length > 0) {
    throw new Error(
      `refusing to report: the measurement was not produced on the frozen instruments\n  ${problems.join("\n  ")}`,
    );
  }
  return [...seen.values()][0]!;
}

/**
 * The model is the deepest instrument: the `ocr` binary is pinned by commit,
 * but the model it calls decides what AOR reports, is configurable, and can be
 * swapped server-side under a fixed id.
 *
 * A row that cannot name the model that answered is not a measurement, so a
 * missing block is a refusal, not a gap in a table. `id` is the served model;
 * `configured` is what the client asked for, so an alias is recorded as an
 * alias instead of being resolved by guesswork.
 */
function aorModelProblems(model: AorModel | undefined, frozen: FrozenInstruments["aor_model"], key: string): string[] {
  if (model === undefined) return [`${key}: no aor model identity`];
  const problems: string[] = [];
  if (model.source !== "observed") {
    problems.push(`${key}: aor model identity is declared, not observed`);
  }
  if (model.provider !== frozen.provider) {
    problems.push(`${key}: aor provider ${model.provider} != frozen ${frozen.provider}`);
  }
  if (model.id !== frozen.id) {
    problems.push(
      `${key}: aor model ${model.id} != frozen ${frozen.id} - the service is answering with a different model than the one this run was frozen against`,
    );
  }
  if (model.params.url !== frozen.url) {
    problems.push(`${key}: aor endpoint ${model.params.url ?? "none"} != frozen ${frozen.url ?? "none"}`);
  }
  if (model.params.configured !== frozen.configured) {
    problems.push(
      `${key}: aor requested model ${model.params.configured ?? "none"} != frozen ${frozen.configured ?? "none"}`,
    );
  }
  return problems;
}

export async function collectJsonl(root: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) out.push(...(await collectJsonl(path)));
    else if (entry.name.endsWith(".jsonl") && !entry.name.startsWith("pairing")) out.push(path);
  }
  return out;
}

export async function loadRuns(root: string): Promise<AcceptanceRowLike[]> {
  // `collect` writes one file; if it is there, it is the whole population. A
  // tree walk would also pick up the plugin's own rows (`B4/review.jsonl`, one
  // row per phase, `pre_decision` instead of `disposition`), which is a
  // different shape measuring a different thing.
  const collected = join(root, "rows.jsonl");
  const files = existsSync(collected) ? [collected] : await collectJsonl(root);
  const rows: AcceptanceRowLike[] = [];
  for (const file of files) {
    for (const line of (await readFile(file, "utf8")).split("\n")) {
      if (line.trim().length === 0) continue;
      rows.push(JSON.parse(line) as AcceptanceRowLike);
    }
  }
  return rows;
}

interface FinalContentSnapshot {
  entries?: Record<string, { path?: string; content?: string | null; missing?: boolean }>;
}

/**
 * Read the final-content snapshot `collect` writes next to `rows.jsonl`.
 *
 * A missing file is `null`, not `""`: an empty file and an unreadable one are
 * different facts, and only the second makes line 3 unmeasurable. The snapshot
 * is keyed by `line3PairKey`, the same identity the pair timeline uses.
 */
export function loadFinalContent(path: string): Map<string, string | null> {
  const raw = JSON.parse(readFileSync(path, "utf8")) as FinalContentSnapshot;
  if (raw.entries === undefined || typeof raw.entries !== "object") {
    throw new Error(`${path} is not a final-content snapshot: entries is required`);
  }
  const out = new Map<string, string | null>();
  for (const [key, entry] of Object.entries(raw.entries)) {
    out.set(key, entry.missing === true || typeof entry.content !== "string" ? null : entry.content);
  }
  return out;
}

/** Trim each line and collapse internal whitespace runs to one space. */
export function normalizedText(text: string): string {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim().replace(/\s+/g, " "))
    .join("\n");
}

/**
 * The GT text line 3 searches for, taken from the label spans of `after`.
 * A span whose normalized text is empty does not take part. Paths are not
 * aligned: a staged sample is one file, and line numbers drift after a rewrite.
 */
function gtSpans(sample: SampleTruth | undefined): string[] {
  if (sample === undefined || sample.after.length === 0) return [];
  const lines = sample.after.split(/\r?\n/);
  const spans: string[] = [];
  for (const label of sample.labels) {
    if (label.cwe === null) continue;
    const start = Math.max(0, label.startLine - 1);
    const end = Math.min(label.endLine, lines.length);
    if (end <= start) continue;
    const text = normalizedText(lines.slice(start, end).join("\n"));
    if (text.length > 0) spans.push(text);
  }
  return spans;
}

/**
 * Ground truth, read through the dataset's own schema.
 *
 * The earlier version hand-wrote the sample-file shape and guessed the field
 * names, and guessed them wrong twice: the self set stores spans as `defects[]`
 * and the class as `sample_cwe`, while the imported sets use `labels[]` and
 * `cwe`. Both mistakes type-checked, because nothing on that boundary was
 * derived from a schema. Reading through `loadDataset` means a renamed field is
 * a compile error and a malformed row is a parse error, instead of a
 * complete-looking report with an empty denominator.
 */
export async function loadTruth(datasetDir: string): Promise<Map<string, SampleTruth>> {
  const { samples } = await loadDataset(datasetDir);
  const truth = new Map<string, SampleTruth>();
  for (const sample of samples) {
    truth.set(sample.sample_id, {
      sample_id: sample.sample_id,
      split: sample.split,
      risk_level: sample.risk_level,
      paired_safe: sample.paired_safe,
      language: sample.language,
      event_kind: sample.event_kind,
      // `cwe` is the manifest's class for this row, already validated as
      // `/^CWE-\d+$/` or null by `AnnotationSample`.
      sample_cwe: sample.cwe,
      labels: sample.labels,
      expected_detectable_by: sample.expected_detectable_by,
      after: sample.after,
    });
  }
  return truth;
}

function tokensOf(row: AcceptanceRowLike): number | null {
  if (typeof row.tokens === "number") return row.tokens;
  if (row.tokens && typeof row.tokens === "object") return row.tokens.total;
  return null;
}

function median(values: number[]): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[middle - 1]! + sorted[middle]!) / 2 : sorted[middle]!;
}

export interface LineResult {
  name: string;
  /**
   * Three states, because "not measured" is not "failed". `na` is for a line the
   * instrument cannot reach at all (a pair whose ratio is undetermined, a row
   * that was never scanned), and it stays in the gate denominator: it is a label,
   * not an exemption. The gate is five lines that must hold simultaneously, so a
   * `na` line can only make it harder.
   */
  state: "pass" | "fail" | "na";
  pass: boolean;
  /** Required when `state === "na"`: why the line cannot be measured. */
  na_reason?: string;
  detail: string;
  metrics?: Record<string, number | string | null>;
}

/** `na` wins over both verdicts: an unmeasured line is never a pass. */
function stateOf(naReason: string | null, pass: boolean): LineResult["state"] {
  if (naReason !== null) return "na";
  return pass ? "pass" : "fail";
}

export interface AcceptanceReport {
  mode: string;
  lines: LineResult[];
  resultsTable: string;
  verdict: string;
}

function table(headers: string[], rows: string[][]): string {
  return [headers, ...rows].map((row) => `| ${row.join(" | ")} |`).join("\n");
}

export function evaluateAcceptance(
  rows: AcceptanceRowLike[],
  truth: Map<string, SampleTruth>,
  gaps: BlockGaps | null,
  options: AcceptanceOptions = {},
): AcceptanceReport {
  const minSamples = options.minSamples ?? 20;
  const minFindings = options.minFindings ?? 20;
  const coverage = options.coverage;
  // Before any number: was this run produced on the frozen tools? A refusal here
  // is the point - a drifted binary produces a complete, plausible report.
  const instruments =
    options.frozenInstruments === undefined
      ? null
      : assertInstrumentIdentity(rows, options.frozenInstruments);
  const modes = new Set(rows.map((row) => row.mode));
  if (modes.size > 1) throw new Error(`live and replay rows must not be mixed: ${[...modes].join(",")}`);
  const mode = [...modes][0] ?? "unknown";
  const rowsSource = options.rowsSource ?? "unknown";
  const ordered = [...rows].sort((a, b) => (a.change_event?.ts ?? 0) - (b.change_event?.ts ?? 0));
  // A live write emits one row per phase. The blocking assertion is a pre
  // decision, while correction anchors only exist on post rows; comparing the
  // phases as one population would double every sample and mix mechanisms.
  const preRows = ordered.filter((row) => row.change_event?.phase === "pre");
  const postRows = ordered.filter((row) => row.change_event?.phase !== "pre");
  // Replay records carry a single already-decided row per sample, so they have
  // no pre rows to separate; live rows always do.
  const blockingRows = preRows.length > 0 ? preRows : ordered;

  const mainRows = blockingRows.filter((row) => row.baseline === "B4");
  const evalPositives = mainRows.filter((row) => {
    const sample = truth.get(row.sample);
    return sample !== undefined && sample.split === "eval" && sample.labels.length > 0;
  });
  // Two denominators, one gate. A row whose language no shipped subset can scan
  // was never attempted: counting it as a miss would report recall as a
  // function of language coverage. It is listed separately instead. A timeout
  // *was* attempted and stays in as a miss.
  const neverScanned = (row: AcceptanceRowLike): boolean =>
    row.review_skip_reason === "language_unsupported" ||
    row.sources.some(
      (source) => source.source === "semgrep" && source.errorKind === "language_unsupported",
    );
  const outOfScope = evalPositives.filter(neverScanned);
  const scannable = evalPositives.filter((row) => !neverScanned(row));
  // `expected_detectable_by` is a non-truth hint (annotation spec §6) and must
  // not select the denominator. The ruleset's *declared* coverage does, and it
  // is a fact about the pinned rules table, decidable before unblinding.
  const coveredSample = (sample: SampleTruth): boolean => {
    if (coverage === undefined) return true;
    const key = cweKey(sample.sample_cwe);
    return key !== null && (coverage.perCwe[key] ?? 0) > 0;
  };
  const covered = (row: AcceptanceRowLike): boolean => {
    const sample = truth.get(row.sample);
    if (sample === undefined) return coverage === undefined;
    return coveredSample(sample);
  };
  const positives = scannable.filter(covered);
  const excluded = scannable.filter((row) => !covered(row));
  const negatives = mainRows.filter((row) => {
    const sample = truth.get(row.sample);
    return sample !== undefined && sample.labels.length === 0;
  });
  // `create` and `edit` are different writes; a pool that only ever edits cannot
  // say anything about the create path, so the split is reported rather than
  // averaged into one number.
  const negativesByKind = new Map<string, number>();
  for (const row of negatives) {
    const kind = truth.get(row.sample)?.event_kind ?? "unknown";
    negativesByKind.set(kind, (negativesByKind.get(kind) ?? 0) + 1);
  }
  const negativeEdits = negativesByKind.get("edit") ?? 0;
  const negativeCreates = negativesByKind.get("create") ?? 0;
  const evaluatedAor = (row: AcceptanceRowLike): boolean => row.aor_participated !== false;
  // A row that never reached AOR cannot be in a denominator about AOR's output:
  // it would count as "no anchor" and as "not corrected" while nothing was asked
  // of it. Counted once per sample - `evaluate` flags both phases of a demoted
  // row, so the set is the population, not the row count. `evaluate` lists them
  // by name before this is called.
  const aorExcluded = new Set(rows.filter((row) => !evaluatedAor(row)).map((row) => row.sample)).size;
  const denied = (row: AcceptanceRowLike): boolean => row.disposition.preDecision === "deny";
  const falsePositive = negatives.filter(denied);
  // Recall's unit is the sample: did the write get caught at all. A positive is
  // written several times per drill (on ds-2: 50 pre rows over 10 samples), so
  // counting rows here multiplies the denominator by the number of writes and
  // turns a 10-sample run into an `n=50` one. Precision's unit stays the
  // finding: of everything the pipeline surfaced, how much names a real defect.
  // Each face has its own denominator, its own gate and its own status.
  const positiveSamples = [...new Set(positives.map((row) => row.sample))];
  const caughtSamples = positiveSamples.filter((sample) =>
    positives.some((row) => row.sample === sample && denied(row)),
  );
  const n = positiveSamples.length;
  const hits = caughtSamples.length;
  const missed = n - hits;
  const recall = n === 0 ? 0 : hits / n;
  const recallGated = n >= minSamples;
  const interval = wilsonInterval(hits, n);
  // Certification is a property of the pinned config, decidable before any row is
  // read: a finding can be denied only when its rule id is listed in its
  // subset's `blockRules` (`semgrep.ts:493`), and an uncertified finding never
  // enters `triggering` (`orchestrator.ts:385`). An empty list for the positives'
  // language means the block face was never wired for it.
  const certifiedRuleCount = (language: string): number => {
    const target = semgrepLanguage(language);
    const rules = new Set<string>();
    for (const subset of options.subsets ?? []) {
      if (!subset.langs.some((lang) => lang.toLowerCase() === target)) continue;
      for (const rule of subset.blockRules) rules.add(rule);
    }
    return rules.size;
  };
  const positiveLanguages = [
    ...new Set(positiveSamples.map((sample) => truth.get(sample)?.language ?? "")),
  ].filter((language) => language.length > 0);
  const certifiedSamples = positiveSamples.filter((sample) => {
    const language = truth.get(sample)?.language;
    return language !== undefined && certifiedRuleCount(language) > 0;
  });
  const uncertifiedSamples = n - certifiedSamples.length;
  const shortLanguage = (language: string): string => {
    const normalized = semgrepLanguage(language);
    if (normalized === "typescript") return "TS";
    if (normalized === "javascript") return "JS";
    if (normalized === "python") return "Python";
    return normalized.toUpperCase();
  };
  const languageLabel = [...new Set(positiveLanguages.map(shortLanguage))].join("/") || "?";
  // An empty block face fails the line (D13: "`block` 档为空则本线不通过") and the
  // detail carries the pre-registered conclusion verbatim. It is not `na`: `na`
  // would leave the gate denominator, and the claim being made here is stronger
  // than "not measured" - at the required precision the dataset has no blocking
  // capability, because the pinned config offers no rule this language may deny
  // on. `subsets === undefined` stays `unknown` rather than `empty`: nothing was
  // looked at, so nothing can be said about the config.
  const blockFaceEmpty = options.subsets !== undefined && n > 0 && certifiedSamples.length === 0;
  // Without the config the certification face is unknown, not empty: printing
  // "0/10 certified" would claim that no rule can block when nobody looked.
  const certifiedText =
    options.subsets === undefined ? "certified=na (config not supplied)" : `certified=${certifiedSamples.length}/${n}`;
  // D13 requires the `n < 15` qualifier in words, not as an implication: a
  // 0/10 with no interval is a descriptive count, and quoting it as a rate would
  // read a small sample as a measured capability.
  const blockConclusion = blockFaceEmpty
    ? `block_face=empty (blockRules is empty for ${languageLabel} in the pinned config) ` +
      `conclusion=在所要求精度下该数据集不具备阻断能力` +
      (n < 15 ? `; n=${n}<15 不具统计意义` : "")
    : "";
  const recallStatus = blockFaceEmpty ? "unblockable" : recallGated ? "gated" : "insufficient_n";
  const inCoverageLanguage = (sample: SampleTruth): boolean =>
    coverage === undefined || semgrepLanguage(sample.language) === coverage.language;
  const evalTruth = [...truth.values()].filter(
    (sample) => sample.split === "eval" && sample.labels.length > 0,
  );
  const gateable = evalTruth.filter(
    (sample) => inCoverageLanguage(sample) && coveredSample(sample),
  );
  const seen = new Set(rows.map((row) => row.sample));
  const availableN = gateable.length;
  const stagedN = gateable.filter((sample) => seen.has(sample.sample_id)).length;

  // `insufficient_n` means "too few samples", and its precondition is that the
  // truth and the rows describe the same population. Zero gateable samples next
  // to a pile of rows is the opposite: the two sides disagree about which rows
  // exist. That produced `n=0 available=0 excluded=10` once, a denominator that
  // looked like a completed measurement. It is a wiring error, and it throws
  // before any number is computed.
  if (availableN === 0) {
    throw new Error(
      `no gateable eval positive: the truth and the rows do not describe the same population ` +
        `(eval positives in the dataset: ${evalTruth.length}, rows seen: ${rows.length}, ` +
        `never scanned: ${outOfScope.length}, outside the declared coverage: ${excluded.length}). ` +
        `This is a wiring error, not a small sample: \`insufficient_n\` requires available >= 1.`,
    );
  }

  const overlapsTruth = (
    finding: { startLine: number; endLine: number },
    sample: SampleTruth,
  ): boolean =>
    sample.labels.some(
      (label) => finding.startLine <= label.endLine && label.startLine <= finding.endLine,
    );
  let findingTp = 0;
  let findingFp = 0;
  let findingWithoutClass = 0;
  for (const row of postRows) {
    const sample = truth.get(row.sample);
    if (sample === undefined || sample.split !== "eval" || row.baseline !== "B4") continue;
    for (const finding of row.findings_merged) {
      if (finding.cwe === null) findingWithoutClass += 1;
      if (overlapsTruth(finding, sample)) findingTp += 1;
      else findingFp += 1;
    }
  }
  const findingN = findingTp + findingFp;
  const precisionMeasurable = negatives.length > 0;
  const precisionGated = precisionMeasurable && findingN >= minFindings;
  const precision = precisionMeasurable && findingN > 0 ? findingTp / findingN : null;
  const precisionStatus = !precisionMeasurable
    ? "no_negatives"
    : findingN >= minFindings
      ? "gated"
      : "insufficient_n";
  const gapSamples = new Set((gaps?.gaps ?? []).map((gap) => gap.sample_id));
  const predictedGap = mainRows.filter((row) => denied(row) && gapSamples.has(row.sample));
  const firstRun = ordered[0]?.change_event?.ts ?? null;
  const preregistered = gaps !== null && firstRun !== null && Date.parse(gaps.preregistered_at) <= firstRun;
  const line1Pass =
    mode === "live" &&
    preregistered &&
    recallGated &&
    precisionGated &&
    recall >= 0.7 &&
    precision !== null &&
    precision >= 0.9 &&
    predictedGap.length === 0;
  const excludedClasses = [...new Set(excluded.map((row) => cweKey(truth.get(row.sample)?.sample_cwe ?? null) ?? "none"))];
  const line1: LineResult = {
    name: "line1: block precision/recall on the covered, scannable eval positives",
    // An empty block face is a failure, not `na` (see `blockFaceEmpty`).
    state: blockFaceEmpty || !line1Pass ? "fail" : "pass",
    pass: line1Pass,
    detail:
      `mode=${mode} recall n=${n} samples (${positives.length} pre rows) ` +
      `(available=${availableN} staged=${stagedN}) hits=${hits} ` +
      `recall=${recall.toFixed(3)} wilson=[${interval === null ? "na" : `${interval.low.toFixed(3)},${interval.high.toFixed(3)}`}] ` +
      `recall_gate=${recallStatus}` +
      `${recallGated || blockFaceEmpty ? "" : " (descriptive, not gated)"} ` +
      `${certifiedText}` +
      `${blockConclusion.length === 0 ? "" : ` ${blockConclusion}`} ` +
      `precision findings=${findingN} tp=${findingTp} precision=${precision === null ? "na" : precision.toFixed(3)} ` +
      `without_class=${findingWithoutClass} ` +
      `precision_gate=${precisionStatus} negatives=${negatives.length} ` +
      `(edit=${negativeEdits} create=${negativeCreates}) ` +
      `excluded=${excluded.length}${excludedClasses.length > 0 ? `(${excludedClasses.join(",")})` : ""} ` +
      `out_of_scope=${outOfScope.length} ` +
      `aor_excluded=${aorExcluded} ` +
      `preregistered_gaps=${preregistered} predicted_gaps=${predictedGap.length}`,
    metrics: {
      /** Recall's denominator: samples, not rows. */
      n,
      k: hits,
      rows: positives.length,
      recall,
      // The number exists even when the gate does not: "cannot be gated" is not
      // the same claim as "was not measured".
      wilson_low: interval?.low ?? null,
      wilson_high: interval?.high ?? null,
      recall_status: recallStatus,
      certified: options.subsets === undefined ? null : certifiedSamples.length,
      uncertified: options.subsets === undefined ? null : uncertifiedSamples,
      block_face: blockFaceEmpty ? "empty" : "measurable",
      available: availableN,
      staged: stagedN,
      not_staged: availableN - stagedN,
      precision,
      findings_n: findingN,
      findings_tp: findingTp,
      findings_without_class: findingWithoutClass,
      precision_status: precisionStatus,
      false_positive: falsePositive.length,
      negatives: negatives.length,
      negatives_edit: negativeEdits,
      negatives_create: negativeCreates,
      missed,
      // Every row that exists, once: positives rows + excluded + out_of_scope.
      scannable: scannable.length,
      out_of_scope: outOfScope.length,
      excluded: excluded.length,
      aor_excluded: aorExcluded,
      excluded_classes: excludedClasses.join(","),
      preregistered: String(preregistered),
    },
  };

  const registryHits = ordered.filter((row) =>
    row.sources.some(
      (source) =>
        source.source === "registry" &&
        source.findings.some((finding) => (finding.evidence ?? "").startsWith("package not found")),
    ),
  );
  const line2Pass = mode === "live" && registryHits.length > 0;
  const line2: LineResult = {
    name: "line2: dependency hallucination closed by a registry hit",
    state: stateOf(null, line2Pass),
    pass: line2Pass,
    detail: `mode=${mode} registry_hits=${registryHits.length}`,
    metrics: { registry_hits: registryHits.length },
  };

  const warned = postRows.filter(
    (row) => row.disposition.postDecision === "inject_warn" && evaluatedAor(row),
  );
  type Line3State = "corrected" | "recurred" | "unfixed" | "not_removed" | "not_measured";
  // B4 and B4g write the same sample names, so a sample-only key merges two
  // independent runs into one timeline: B4g's staged write would then count as
  // a later write of B4, and B4g's terminal warning would turn B4's edits into
  // "unfixed". A baseline is a separate run; key by baseline and sample.
  const line3Key = (row: Pick<AcceptanceRowLike, "baseline" | "sample">): string =>
    line3PairKey(row.baseline, row.sample);
  const perSample = new Map<string, AcceptanceRowLike[]>();
  for (const row of postRows) {
    const key = line3Key(row);
    const list = perSample.get(key) ?? [];
    list.push(row);
    perSample.set(key, list);
  }
  // Line 3 decides per warned pair, from the first warning onward. Detection
  // staying silent is not evidence the defect is gone: once a write follows and
  // the class does not return, the GT text is looked up in the final file.
  // `not_measured` is a missing/unreadable snapshot, not an empty file.
  const finalContent = options.finalContent;
  const contentCriterion = finalContent !== undefined;
  let contentChecked = 0;
  let contentMissing = 0;
  const contentVerdict = (
    pair: string,
    sample: string,
  ): { state: Line3State; checked: boolean; missing: boolean } => {
    if (finalContent === undefined) return { state: "corrected", checked: false, missing: false };
    const content = finalContent.get(pair);
    if (content === undefined || content === null) {
      return { state: "not_measured", checked: false, missing: true };
    }
    const spans = gtSpans(truth.get(sample));
    if (spans.length === 0) return { state: "corrected", checked: false, missing: false };
    const final = normalizedText(content);
    return {
      state: spans.some((span) => final.includes(span)) ? "not_removed" : "corrected",
      checked: true,
      missing: false,
    };
  };
  const rowStates: Array<{ row: AcceptanceRowLike; state: Line3State }> = [];
  const sampleStates = new Map<string, Line3State>();
  const warnedSamples = [...new Set(warned.map((row) => row.sample))];
  const warnedPairs = [...new Set(warned.map(line3Key))];
  const reappearsAnywhere = (
    later: AcceptanceRowLike[],
    classes: ReadonlySet<string>,
  ): boolean =>
    later.some((candidate) =>
      candidate.findings_merged.some((finding) => finding.cwe !== null && classes.has(finding.cwe)),
    );
  for (const pair of warnedPairs) {
    const separator = pair.indexOf("\u0000");
    const baseline = pair.slice(0, separator);
    const sample = pair.slice(separator + 1);
    const classes = new Set(
      (truth.get(sample)?.labels ?? [])
        .map((label) => label.cwe)
        .filter((cwe): cwe is string => cwe !== null),
    );
    // A warned sample without ground-truth classes (e.g. the dependency probe)
    // cannot carry line 3's assertion either way.
    if (classes.size === 0) continue;
    const rows = perSample.get(pair) ?? [];
    const warnedRows = rows.filter((row) => row.disposition.postDecision === "inject_warn");
    // Sample level is judged from the first warning onward: a warning on the
    // sample's final write cannot be told apart from "acted and stopped" by row
    // position, and reading it as inaction is what marked every B4g sample
    // `unfixed` while B4 had edited all of them. The gate's question is whether
    // a warning produced any later write, and whether the class survived it.
    const firstWarnTs = Math.min(...warnedRows.map((row) => row.change_event?.ts ?? 0));
    const afterFirstWarn = rows.filter((row) => (row.change_event?.ts ?? 0) > firstWarnTs);
    let state: Line3State;
    if (afterFirstWarn.length === 0) {
      state = "unfixed";
    } else if (reappearsAnywhere(afterFirstWarn, classes)) {
      state = "recurred";
    } else {
      const verdict = contentVerdict(pair, sample);
      if (verdict.checked) contentChecked += 1;
      if (verdict.missing) contentMissing += 1;
      state = verdict.state;
    }
    sampleStates.set(`${baseline}/${sample}`, state);
    for (const row of warnedRows) {
      const later = rows.filter(
        (candidate) => (candidate.change_event?.ts ?? 0) > (row.change_event?.ts ?? 0),
      );
      let rowState: Line3State;
      if (later.length === 0) {
        rowState = "unfixed";
      } else if (reappearsAnywhere(later, classes)) {
        rowState = "recurred";
      } else {
        rowState = contentVerdict(pair, sample).state;
      }
      rowStates.push({ row, state: rowState });
    }
  }
  const samplesIn = (state: Line3State): string[] =>
    [...sampleStates].filter(([, value]) => value === state).map(([sample]) => sample);
  const correctedSamples = samplesIn("corrected");
  const recurredSamples = samplesIn("recurred");
  const unfixedSamples = samplesIn("unfixed");
  const notRemovedSamples = samplesIn("not_removed");
  const notMeasuredSamples = samplesIn("not_measured");
  const classedSamples = sampleStates.size;
  const rowsIn = (state: Line3State): number =>
    rowStates.filter((entry) => entry.state === state).length;
  // D13's denominator is one entry per warned (baseline, sample) pair, because
  // each baseline is an independent run: B4 and B4g stage and edit the same
  // sample names, so pooling them by name let B4g's single write answer for B4.
  // The gate is read off sample level — every warned pair must show a write
  // after its first warning and no return of the ground-truth class. Row states
  // stay in the detail as a diagnostic; a terminal warning is not inaction.
  const line3Pass = classedSamples > 0 && correctedSamples.length === classedSamples;
  const criterion = contentCriterion ? "gt-text-absent" : "detection-only";
  const naOr = (value: number): number | string => (contentCriterion ? value : "na");
  const notMeasuredRelevant = contentCriterion;
  const notMeasuredText = notMeasuredRelevant ? notMeasuredSamples.length : "na";
  const line3: LineResult = {
    name: "line3: no repeat of the same class after a correction",
    state: stateOf(null, line3Pass),
    pass: line3Pass,
    detail:
      `warned_rows=${warned.length} warned_samples=${warnedSamples.length} warned_pairs=${warnedPairs.length} ` +
      `classed=${classedSamples} samples corrected=${correctedSamples.length} ` +
      `recurred=${recurredSamples.length}${recurredSamples.length > 0 ? `(${recurredSamples.join(",")})` : ""} ` +
      `unfixed=${unfixedSamples.length}${unfixedSamples.length > 0 ? `(${unfixedSamples.join(",")})` : ""} ` +
      `not_removed=${naOr(notRemovedSamples.length)}` +
      `${notRemovedSamples.length > 0 ? `(${notRemovedSamples.join(",")})` : ""} ` +
      `not_measured=${notMeasuredText}` +
      `${notMeasuredSamples.length > 0 ? `(${notMeasuredSamples.join(",")})` : ""} ` +
      `| rows corrected=${rowsIn("corrected")} recurred=${rowsIn("recurred")} unfixed=${rowsIn("unfixed")} ` +
      `not_removed=${naOr(rowsIn("not_removed"))} ` +
      `not_measured=${notMeasuredRelevant ? rowsIn("not_measured") : "na"}` +
      ` | criterion=${criterion} content_checked=${naOr(contentChecked)} ` +
      `content_missing=${naOr(contentMissing)} ` +
      `content_not_measured=${contentCriterion ? 0 : classedSamples}`,
    metrics: {
      warned_rows: warned.length,
      warned_samples: warnedSamples.length,
      warned_pairs: warnedPairs.length,
      classed: classedSamples,
      corrected: correctedSamples.length,
      recurred: recurredSamples.length,
      unfixed: unfixedSamples.length,
      not_removed: contentCriterion ? notRemovedSamples.length : null,
      not_measured: notMeasuredRelevant ? notMeasuredSamples.length : null,
      classed_rows: rowStates.length,
      corrected_rows: rowsIn("corrected"),
      recurred_rows: rowsIn("recurred"),
      unfixed_rows: rowsIn("unfixed"),
      not_removed_rows: rowsIn("not_removed"),
      not_measured_rows: rowsIn("not_measured"),
      content_checked: contentCriterion ? contentChecked : null,
      content_missing: contentCriterion ? contentMissing : null,
      criterion,
    },
  };

  // Line 4 pairs B4 against B4g on eight defect-free low-risk samples. The
  // population is "pairs that were actually measured under both baselines",
  // not the first eight low-risk rows in manifest order: that order mixed in
  // fit-split positives that the drill never stages, so the pairing could only
  // ever find a handful and the line failed for a bookkeeping reason.
  const pairedCandidates = [...truth.values()]
    .filter((sample) => sample.risk_level === "low" && sample.labels.length === 0)
    .filter(
      (sample) =>
        postRows.some((row) => row.sample === sample.sample_id && row.baseline === "B4") &&
        postRows.some((row) => row.sample === sample.sample_id && row.baseline === "B4g"),
    )
    .sort((a, b) => (a.sample_id < b.sample_id ? -1 : a.sample_id > b.sample_id ? 1 : 0));
  const lowRisk = pairedCandidates.slice(0, 8);
  /**
   * A tier-0 row never asks AOR anything, so its token cost is 0 by
   * construction. That 0 has to be read off a recorded decision: every row the
   * current orchestrator writes says `aor_invoked`, `false` on a tier-0 row.
   * A null token count is never, on its own, read as 0 (ADR-0008); a null on a
   * row that *did* invoke AOR stays `na`.
   *
   * `tier: 0` alone is not enough to derive 0: a static-fallback tier 0 skipped
   * AOR for a different reason, and a row that says tier 0 while carrying an
   * `aor` source is self-contradictory. The honest read of a contradiction is
   * `na`, never 0.
   *
   * The `tier` branch below exists only for `rows.jsonl` written before the
   * field was added (the archived ds-2 run is one). New runs are refused by
   * `collect` when any row lacks the field, so the branch cannot be reached
   * from a new run. Delete it once every run that still needs re-reading
   * carries `aor_invoked`; do not keep two ways to say one thing.
   */
  const tokenCost = (
    row: AcceptanceRowLike,
  ): { value: number; derived: boolean; basis: "measured" | "aor_invoked" | "tier" } | null => {
    const measured = tokensOf(row);
    if (measured !== null) return { value: measured, derived: false, basis: "measured" };
    if (row.aor_invoked === true) return null;
    if (row.aor_invoked === false) return { value: 0, derived: true, basis: "aor_invoked" };
    const aorInSources = row.sources.some((source) => source.source === "aor");
    const legacyTier0 = row.tier === 0 && row.tier_source === "triage" && !aorInSources;
    return legacyTier0 ? { value: 0, derived: true, basis: "tier" } : null;
  };
  const pairs: Array<{
    sample: string;
    eventKind: string;
    latencyRatio: number;
    tokenRatio: number | null;
    /** True when the ratio rests on a 0 derived from "AOR was never asked". */
    derived: boolean;
    /** How that 0 was established; printed so the record and the report agree. */
    basis: "measured" | "aor_invoked" | "tier";
    b4Tokens: number | null;
    b4gTokens: number | null;
  }> = [];
  for (const sample of lowRisk) {
    const b4 = postRows.find((row) => row.sample === sample.sample_id && row.baseline === "B4");
    const b4g = postRows.find((row) => row.sample === sample.sample_id && row.baseline === "B4g");
    if (!b4 || !b4g) continue;
    const latencyRatio = b4g.latency_ms === 0 ? Number.POSITIVE_INFINITY : b4.latency_ms / b4g.latency_ms;
    const t4 = tokenCost(b4);
    const t4g = tokenCost(b4g);
    pairs.push({
      sample: sample.sample_id,
      eventKind: sample.event_kind ?? "unknown",
      latencyRatio,
      tokenRatio: t4 !== null && t4g !== null && t4g.value !== 0 ? t4.value / t4g.value : null,
      derived: t4?.derived === true || t4g?.derived === true,
      basis: t4?.basis ?? t4g?.basis ?? "measured",
      b4Tokens: t4?.value ?? null,
      b4gTokens: t4g?.value ?? null,
    });
  }
  const medianLatency = median(pairs.map((pair) => pair.latencyRatio));
  // Two medians, because they answer two questions. The raw one is what was
  // measured on both sides; it is `na` when a side was never asked. The derived
  // one is the line's registered criterion and exists only where the 0 came from
  // `aor_invoked: false`; both are printed together so neither can be quoted as
  // if it were the other.
  const rawMedianTokens = median(
    pairs.filter((pair) => !pair.derived && pair.tokenRatio !== null).map((pair) => pair.tokenRatio!),
  );
  const medianTokens = median(
    pairs.map((pair) => pair.tokenRatio).filter((value): value is number => value !== null),
  );
  const derivedPairs = pairs.filter((pair) => pair.derived).length;
  const derivedBases = { aor_invoked: 0, tier: 0 };
  for (const pair of pairs) {
    if (!pair.derived) continue;
    if (pair.basis === "aor_invoked") derivedBases.aor_invoked += 1;
    else derivedBases.tier += 1;
  }
  const basisText =
    `aor_invoked:false ${derivedBases.aor_invoked}, tier 0 via triage ${derivedBases.tier}`;
  const b4gTokenRange = (() => {
    const values = pairs.map((pair) => pair.b4gTokens).filter((value): value is number => value !== null);
    return values.length === 0 ? null : `${Math.min(...values)}-${Math.max(...values)}`;
  })();
  // `pairs.length === 8` only says eight pairs *exist*; it says nothing about
  // whether their ratios could be computed. A pair whose side asked AOR and lost
  // the token count (budget skip, cache hit, timeout) has no ratio, and leaving
  // it out of the median while still passing on "median <= 1" would let seven
  // undetermined pairs ride on one measured 0. So an undetermined pair makes the
  // line `na`, which is strictly worse than `fail` on a gate line: `na` never
  // counts as a pass, and it also leaves the gate denominator, so the gate can
  // never reach G/G. That is the point - it must not be possible to turn "we do
  // not know" into a passing line by removing the unknown row.
  const undetermined = pairs.filter((pair) => pair.tokenRatio === null).length;
  const line4Pass =
    pairs.length === 8 && undetermined === 0 && medianTokens !== null && medianTokens <= 1;
  const line4NaReason =
    undetermined === 0
      ? null
      : `undetermined_pairs (${undetermined}/${pairs.length} pairs have no computable token ratio: ` +
        `a row asked AOR and recorded no token count, or a baseline recorded 0 tokens)`;
  // The ratio is a fact about the tree the drill wrote, and on its own it reads as
  // "the ladder saved tokens on this corpus". The counterfactual - measured on the
  // pinned repositories, not inside the run - says the opposite, so it travels in
  // the detail: whoever quotes the ratio quotes the sentence with it.
  const counterfactual = options.stagedContext;
  const tier0 = counterfactual === undefined
    ? "upstream_tier0=na"
    : `upstream_tier0=${counterfactual.pairs_tier0}/${counterfactual.pairs_measured}`;
  const counterfactualNote =
    counterfactual === undefined
      ? "counterfactual=not_measured (no staged-context artefact: the upstream tier of these rows was never derived)"
      : counterfactual.rows_tier0 === 0 && counterfactual.pairs_tier0 === 0
        ? "counterfactual=" +
          `本行验证阶梯在「爆炸半径确实小于边界」时的花费单调性；本语料 ${counterfactual.rows_measured} 个可测行` +
          `无一为 tier 0（最小 ${counterfactual.min_importers ?? "?"} 个 importer，边界 ` +
          `\`filesMax=${counterfactual.files_max}\`），故该语料上阶梯不产生节省。观测到的比值属于构造拓扑。`
        : `counterfactual=contradicted (${counterfactual.rows_tier0}/${counterfactual.rows_measured} measurable ` +
          `rows would be tier 0 upstream, so the registered reading no longer applies)`;
  const line4: LineResult = {
    name: "line4: B4 vs B4g paired token/latency ratios on 8 low-risk samples",
    state: stateOf(line4NaReason, line4Pass),
    pass: line4Pass,
    ...(line4NaReason === null ? {} : { na_reason: line4NaReason }),
    detail:
      `source=${rowsSource} pairs=${pairs.length} undetermined=${undetermined} ` +
      `median_token_ratio=${rawMedianTokens?.toFixed(3) ?? "na"}` +
      ` (raw: measured on both sides for ${pairs.filter((pair) => !pair.derived && pair.tokenRatio !== null).length}/${pairs.length} pairs) ` +
      (derivedPairs > 0
        ? `median_token_ratio_derived=${medianTokens?.toFixed(3) ?? "na"} ` +
          `(derived: ${derivedPairs}/${pairs.length} pairs had AOR not invoked [${basisText}] ` +
          `-> AOR calls 0; B4g tokens ${b4gTokenRange ?? "?"}) `
        : "") +
      `median_latency_ratio=${medianLatency?.toFixed(3) ?? "na"} ` +
      `available_pairs=${pairedCandidates.length} ${tier0} ${counterfactualNote}`,
    metrics: {
      pairs: pairs.length,
      rows_source: rowsSource,
      /** What was measured on both sides. `null` here is not a 0. */
      median_token_ratio: rawMedianTokens,
      /** The registered criterion, where a 0 is derived from `aor_invoked: false`. */
      median_token_ratio_derived: derivedPairs > 0 ? medianTokens : null,
      tokens_derived_pairs: derivedPairs,
      undetermined_pairs: undetermined,
      median_latency_ratio: medianLatency,
      upstream_tier0: counterfactual?.pairs_tier0 ?? null,
      upstream_tier0_measured: counterfactual?.pairs_measured ?? null,
    },
  };

  const anchored = warned.filter(
    (row) =>
      typeof row.disposition.text === "string" &&
      row.disposition.text.includes("[CRS-WARN]") &&
      /CWE-\d+|\.\w{1,5}:\d+/.test(row.disposition.text),
  );
  const line5Pass = anchored.length > 0 && anchored.length === warned.length;
  const line5: LineResult = {
    // This checks the generated text, not the request the agent received: it
    // passes whenever the template carries a path/line token, including when
    // delivery failed. Naming it "visible on the next request" claimed evidence
    // this line never observes.
    name: "line5: correction text carries an anchor (template self-check)",
    state: stateOf(null, line5Pass),
    pass: line5Pass,
    detail: `warned=${warned.length} anchored=${anchored.length} | self-check, not delivery evidence`,
    metrics: { warned: warned.length, anchored: anchored.length },
  };

  // "禁静默丢弃": every class that appears in the eval positives gets a row,
  // including the ones the ruleset cannot see, with its declared rule count.
  const coverageRows: string[][] = [];
  if (coverage !== undefined) {
    const classes = [
      ...new Set(
        evalPositives.map((row) => cweKey(truth.get(row.sample)?.sample_cwe ?? null) ?? "none"),
      ),
    ].sort();
    for (const key of classes) {
      const rowsInClass = evalPositives.filter(
        (row) => (cweKey(truth.get(row.sample)?.sample_cwe ?? null) ?? "none") === key,
      );
      const declared = coverage.perCwe[key] ?? 0;
      coverageRows.push([
        key === "none" ? "(no CWE)" : `CWE-${key}`,
        String(declared),
        String(rowsInClass.length),
        declared > 0 ? "no" : "yes - ruleset declares no rule",
      ]);
    }
  }

  const resultsTable = [
    ...(instruments === null
      ? ["instruments: not asserted (no frozen pin supplied)"]
      : [
          "instruments (observed in the reported process, equal to the pin):",
          "",
          table(
            ["tool", "version", "commit", "source"],
            [
              [
                instruments.semgrep.name,
                instruments.semgrep.version,
                instruments.semgrep.commit ?? "-",
                instruments.semgrep.source,
              ],
              [
                instruments.ocr.name,
                instruments.ocr.version,
                instruments.ocr.commit ?? "-",
                instruments.ocr.source,
              ],
            ],
          ),
          "",
          table(
            ["aor model", "served id", "requested", "endpoint", "source"],
            [
              [
                instruments.aor_model.provider,
                instruments.aor_model.id,
                instruments.aor_model.params.configured ?? "-",
                instruments.aor_model.params.url ?? "-",
                instruments.aor_model.source,
              ],
            ],
          ),
          "",
          "The model is the deepest instrument: `ocr`'s commit says which client asked, " +
            "the served id says which model answered. Both are compared with the frozen pin.",
        ]),
    "",
    table(
      ["line", "state", "detail"],
      [line1, line2, line3, line4, line5].map((line) => [
        line.name,
        line.state.toUpperCase(),
        line.detail,
      ]),
    ),
    "",
    "line1 units (the two faces do not share a denominator):",
    "",
    table(
      ["face", "unit", "n", "gate", "status"],
      [
        [
          "recall",
          "sample",
          `${n} samples (${positives.length} pre rows)`,
          `>= ${minSamples}`,
          recallStatus === "gated"
            ? `gated (${certifiedText})`
            : recallStatus === "unblockable"
              ? `unblockable (${certifiedText}; 结论：在所要求精度下该数据集不具备阻断能力)`
              : `insufficient_n (descriptive, not gated; ${certifiedText})`,
        ],
        [
          "precision",
          "finding",
          String(findingN),
          `>= ${minFindings}`,
          precisionStatus === "gated"
            ? "gated"
            : precisionStatus === "no_negatives"
              ? "no_negatives (descriptive, not gated)"
              : "insufficient_n (descriptive, not gated)",
        ],
      ],
    ),
    "",
    `line1 false-positive denominator: ${negatives.length} defect-free rows ` +
      `(${negativeEdits} edit, ${negativeCreates} create)` +
      (negativeCreates > 0
        ? `; the create path is a smoke sample (n=${negativeCreates}) and no precision claim is made for it`
        : ""),
    ...(availableN === stagedN
      ? []
      : ["", `shortfall: ${availableN} eval positives are gateable, ${stagedN} were staged`]),
    "",
    table(
      ["sample", "event", "B4/B4g token ratio", "B4/B4g latency ratio"],
      pairs.map((pair) => [
        pair.sample,
        pair.eventKind,
        `${pair.tokenRatio?.toFixed(3) ?? "na"}${pair.derived ? " *" : ""}`,
        pair.latencyRatio.toFixed(3),
      ]),
    ),
    ...(derivedPairs === 0
      ? []
      : [
          "",
          `* derived: AOR was never asked on the B4 row (${basisText}), so its AOR cost is 0 by ` +
            `construction rather than unmeasured; the B4g row measured ${b4gTokenRange ?? "?"} tokens. ` +
            `The raw ratio for those pairs is \`na\`, and both numbers are printed above.`,
        ]),
    ...(coverageRows.length > 0
      ? [
          "",
          `line1 denominator by class (declared ${coverage?.language ?? "?"} rules):`,
          "",
          table(["class", "declared rules", "eval rows", "outside line1"], coverageRows),
        ]
      : []),
    ...(outOfScope.length > 0
      ? [
          "",
          `line1 out of scope (never attempted: no subset for the row's language): ` +
            `${outOfScope.length} row(s) - ${outOfScope.map((row) => row.sample).join(", ")}`,
        ]
      : []),
  ].join("\n");

  const lineEntries = [line1, line2, line3, line4, line5];
  // Five lines, all of them in the denominator: the acceptance criterion is that
  // the five hold simultaneously (D13), so `na` is a label and not an exemption.
  // It is listed next to the count, never subtracted from it.
  const naLines = lineEntries.filter((line) => line.state === "na");
  const passedLines = lineEntries.filter((line) => line.state === "pass");
  const verdict = [
    `# 验收结论（${mode}）`,
    "",
    `闸门 ${passedLines.length}/${lineEntries.length}` +
      `${naLines.length === 0 ? "" : `（na ${naLines.length}）`} 通过（${mode}）`,
    "",
    instruments === null
      ? "量具身份：未核对（未提供冻结值）。"
      : `量具身份：semgrep ${instruments.semgrep.version}（observed）、` +
        `ocr ${instruments.ocr.version}（${instruments.ocr.commit ?? "no commit"}，observed）、` +
        `AOR 模型 ${instruments.aor_model.id}（requested ${instruments.aor_model.params.configured ?? "-"}，` +
        `${instruments.aor_model.params.url ?? "-"}，observed），与钉定值一致。`,
    "",
    "结果表见 report.md；本文件只给结论，不把接口通过当质量结论。",
    "",
    "line1 的分母按单位分开：召回以样本计（每个漏洞样本是否被抓到），" +
      `精度以 finding 计（每条 finding 是否落在真值行上）。召回 ${n} / 门槛 ${minSamples}（${recallStatus}，` +
      `available ${availableN} staged ${stagedN}）；精度 ${findingN} / 门槛 ${minFindings}（${precisionStatus}）。`,
    ...(blockFaceEmpty
      ? [
          "",
          "line1 结论（预注册句，D13）：在所要求精度下该数据集不具备阻断能力。" +
            `依据：钉定配置对 ${languageLabel} 的 \`blockRules\` 为空，certified 0/${n} ⇒ 没有任何 finding 能被认证、` +
            `\`deny\` 不可达。n=${n}${n < 15 ? " < 15，不具统计意义" : ""}。` +
            "该结论不读作「检测器漏检」：0 是配置面的事实，不是检测能力的度量。",
        ]
      : []),
    ...(recallGated || blockFaceEmpty
      ? []
      : [
          "",
          `召回面 insufficient_n：recall=${recall.toFixed(3)}（${hits}/${n}）` +
            `${interval === null ? "" : `，Wilson 95% [${interval.low.toFixed(3)}, ${interval.high.toFixed(3)}]`}，` +
            "仅作描述性报告，不进门禁；“测不了”与“没测”是两回事。",
        ]),
    ...(classedSamples === 0
      ? []
      : [
          "",
          `line3 的判据是「每条 warn 均被处理」，不是「大部分被处理」：同一 classed 样本内 5 条 warn 已修、` +
            `1 条未处理，该样本整条记 \`unfixed\`（优先级 unfixed > recurred > not_measured > not_removed > corrected）。` +
            `所以 corrected ${correctedSamples.length}/${classedSamples} 读作「闭环合上的样本数为 ${correctedSamples.length}」，` +
            `不是「多数失败」。本线不设容忍度；将来若要容忍度，须是新的预注册阈值，而不是本次读数的注脚。`,
        ]),
    ...(naLines.length === 0
      ? []
      : [
          "",
          "na（不可测，单列）：" +
            naLines
              .map((line) => `${line.name.split(":")[0]} — ${line.na_reason ?? ""}`)
              .join("；") +
            "。`na` 不是豁免：它不记为通过，闸门分母恒为 5 条（五条须同时成立），" +
            "故任一条 na 都会使通过数至多 4，闸门必然失败 —— 闸线上的 na 劣于 FAIL，这是反空转设计，不因读数难看而豁免。",
        ]),
    ...(availableN === stagedN
      ? []
      : ["", `available ${availableN} 条可门禁的 eval 正样本中有 ${availableN - stagedN} 条未入演练（staged ${stagedN}），短缺来自选样上限而非检测结果。`]),
    ...(negativeCreates === 0
      ? []
      : [
          "",
          `精度分母含 ${negativeCreates} 条 create 样本：它们只证明新建文件路径不是死代码，` +
            `n=${negativeCreates} 不支撑任何精度主张。`,
        ]),
    ...(coverage === undefined
      ? []
      : [
          "",
          `line1 分母口径：按钉定规则表声明的 ${coverage.language} 规则分面，` +
            `${excluded.length} 条 eval 正样本因规则集无该类规则不在分母内（见结果表末表）。`,
        ]),
    ...(outOfScope.length === 0
      ? []
      : [
          "",
          `line1 另将 ${outOfScope.length} 条 eval 正样本单列为 out_of_scope：其语言无任何已装载子集，` +
            `系统从未尝试扫描，故不计入分母。timeout 属"试过、失败"，仍计为未命中。`,
        ]),
    "",
  ].join("\n");

  return { mode, lines: lineEntries, resultsTable, verdict };
}

async function main(): Promise<void> {
  // No default: walking a tree for `*.jsonl` is how replay rows, plugin rows and
  // a stale live staging all end up in one population. The evaluator is pointed
  // at one collected file, and the drill's `evaluate` does exactly that.
  const runsDir = arg("--runs", "");
  if (runsDir.length === 0) {
    throw new Error("--runs <dir with rows.jsonl> is required; this script does not scan a tree");
  }
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const gapsPath = resolve(arg("--gaps", "artifacts/block-gaps.json"));
  const outDir = resolve(arg("--out", "artifacts/acceptance"));
  const rulesPath = resolve(arg("--rules", "research/semgrep-bench/snapshot/rules_table.json"));
  const declared = declaredCoverage(loadRulesTable(rulesPath), arg("--language", "ts"));
  const gaps = existsSync(gapsPath) ? (JSON.parse(await readFile(gapsPath, "utf8")) as BlockGaps) : null;
  // The pin comes from the preregistration, not from the config: the config is
  // the thing under test, and a report that reads its own goalposts can move
  // them. The rows must agree with the frozen values or no number is printed.
  const pin = loadFrozenPin();
  // Line 4's counterfactual lives outside the run by construction (it is measured
  // on the pinned repositories). Optional: a replay report has no staged tree, and
  // then the detail says the measurement is absent instead of quoting zero.
  const stagedContextPath = resolve(arg("--staged-context", "artifacts/staged-context.json"));
  // The certified block face comes from the config, not from the run: the run
  // records only its hash, and `blockRules` is wiring rather than a result.
  const configPath = resolve(arg("--config", "configs/b4.json"));
  // The snapshot `collect` writes sits beside rows.jsonl. Absent means the run
  // predates it, and line 3 then says `criterion=detection-only` rather than
  // reading the absence as "no content remained".
  const finalContentPath = join(resolve(runsDir), "final-content.json");
  const finalContent = existsSync(finalContentPath) ? loadFinalContent(finalContentPath) : undefined;
  const report = evaluateAcceptance(await loadRuns(resolve(runsDir)), await loadTruth(datasetDir), gaps, {
    coverage: { language: declared.language, perCwe: coverageCounts(declared) },
    frozenInstruments: pin,
    subsets: certifiedSubsets(configPath),
    ...(existsSync(stagedContextPath) ? { stagedContext: tier0Counterfactual(stagedContextPath) } : {}),
    ...(finalContent === undefined ? {} : { finalContent }),
  });
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "report.md"), `# 验收结果表（${report.mode}）\n\n${report.resultsTable}\n`, "utf8");
  await writeFile(join(outDir, "verdict.md"), report.verdict, "utf8");
  await writeFile(
    join(outDir, "verdict.json"),
    `${JSON.stringify(
      report.lines.map(({ name, state, pass, na_reason, metrics }) => ({
        name,
        state,
        pass,
        ...(na_reason === undefined ? {} : { na_reason }),
        metrics,
      })),
      null,
      2,
    )}\n`,
    "utf8",
  );
  process.stdout.write(
    `${report.lines.map((line) => `${line.state.toUpperCase()} ${line.name}`).join("\n")}\n`,
  );
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/acceptance.ts")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

export type { ReviewRow, RunRecord };
