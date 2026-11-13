import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
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

export interface AcceptanceOptions {
  minSamples?: number;
  /** Precision's gate counts findings, not samples; a separate unit needs its own n. */
  minFindings?: number;
  /** Absent means "coverage unknown" - then every labelled eval sample counts. */
  coverage?: RuleCoverage;
  /**
   * What the five numbers are allowed to have been produced on. When given, a
   * mismatch refuses the report instead of warning about it: the failure mode
   * this guards is a complete-looking artefact built on a different binary.
   */
  frozenInstruments?: FrozenInstruments;
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
): Instruments {
  const problems: string[] = [];
  if (rows.length === 0) problems.push("no rows to evaluate");
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
  pass: boolean;
  detail: string;
  metrics?: Record<string, number | string | null>;
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
  const denied = (row: AcceptanceRowLike): boolean => row.disposition.preDecision === "deny";
  const truePositive = positives.filter(denied);
  const falsePositive = negatives.filter(denied);
  const missed = positives.length - truePositive.length;
  // Recall's unit is the sample: did the write get caught at all. Precision's
  // unit is the finding: of everything the pipeline surfaced, how much names a
  // real defect. Sharing one `n` between them mixed the units, so each face has
  // its own denominator, its own gate and its own status.
  const n = positives.length;
  const hits = truePositive.length;
  const recall = n === 0 ? 0 : hits / n;
  const recallGated = n >= minSamples;
  const interval = wilsonInterval(hits, n);
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
  for (const row of postRows) {
    const sample = truth.get(row.sample);
    if (sample === undefined || sample.split !== "eval" || row.baseline !== "B4") continue;
    for (const finding of row.findings_merged) {
      if (overlapsTruth(finding, sample)) findingTp += 1;
      else findingFp += 1;
    }
  }
  const findingN = findingTp + findingFp;
  const precisionMeasurable = negatives.length > 0;
  const precisionGated = precisionMeasurable && findingN >= minFindings;
  const precision = precisionMeasurable && findingN > 0 ? findingTp / findingN : null;
  const recallStatus = recallGated ? "gated" : "insufficient_n";
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
    pass: line1Pass,
    detail:
      `mode=${mode} recall n=${n} (available=${availableN} staged=${stagedN}) hits=${hits} ` +
      `recall=${recall.toFixed(3)} wilson=[${interval === null ? "na" : `${interval.low.toFixed(3)},${interval.high.toFixed(3)}`}] ` +
      `recall_gate=${recallStatus}${recallGated ? "" : " (descriptive, not gated)"} ` +
      `precision findings=${findingN} tp=${findingTp} precision=${precision === null ? "na" : precision.toFixed(3)} ` +
      `precision_gate=${precisionStatus} negatives=${negatives.length} ` +
      `(edit=${negativeEdits} create=${negativeCreates}) ` +
      `excluded=${excluded.length}${excludedClasses.length > 0 ? `(${excludedClasses.join(",")})` : ""} ` +
      `out_of_scope=${outOfScope.length} ` +
      `preregistered_gaps=${preregistered} predicted_gaps=${predictedGap.length}`,
    metrics: {
      n,
      k: hits,
      recall,
      // The number exists even when the gate does not: "cannot be gated" is not
      // the same claim as "was not measured".
      wilson_low: interval?.low ?? null,
      wilson_high: interval?.high ?? null,
      recall_status: recallStatus,
      available: availableN,
      staged: stagedN,
      not_staged: availableN - stagedN,
      precision,
      findings_n: findingN,
      findings_tp: findingTp,
      precision_status: precisionStatus,
      false_positive: falsePositive.length,
      negatives: negatives.length,
      negatives_edit: negativeEdits,
      negatives_create: negativeCreates,
      missed,
      // Every row that exists, once: n + excluded + out_of_scope = eval positives.
      scannable: scannable.length,
      out_of_scope: outOfScope.length,
      excluded: excluded.length,
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
  const line2: LineResult = {
    name: "line2: dependency hallucination closed by a registry hit",
    pass: mode === "live" && registryHits.length > 0,
    detail: `mode=${mode} registry_hits=${registryHits.length}`,
    metrics: { registry_hits: registryHits.length },
  };

  const warned = postRows.filter((row) => row.disposition.postDecision === "inject_warn");
  const perSample = new Map<string, AcceptanceRowLike[]>();
  for (const row of postRows) {
    const list = perSample.get(row.sample) ?? [];
    list.push(row);
    perSample.set(row.sample, list);
  }
  const repeats: string[] = [];
  const corrected: string[] = [];
  const classed: AcceptanceRowLike[] = [];
  for (const row of warned) {
    const classes = new Set(
      (truth.get(row.sample)?.labels ?? [])
        .map((label) => label.cwe)
        .filter((cwe): cwe is string => cwe !== null),
    );
    // A warned sample without ground-truth classes (e.g. the dependency probe)
    // cannot carry line 3's assertion either way.
    if (classes.size === 0) continue;
    classed.push(row);
    // Line 3: after the correction lands, the same class must not reappear in
    // that sample's later writes (the corrected file), for up to two fixes.
    const later = (perSample.get(row.sample) ?? []).filter(
      (candidate) =>
        (candidate.change_event?.ts ?? 0) > (row.change_event?.ts ?? 0),
    );
    const reappeared = later.some((candidate) =>
      candidate.findings_merged.some((finding) => finding.cwe !== null && classes.has(finding.cwe)),
    );
    if (later.length === 0) {
      repeats.push(`${row.sample}:unfixed`);
      continue;
    }
    if (reappeared) repeats.push(`${row.sample}:same-class`);
    else corrected.push(row.sample);
  }
  const line3: LineResult = {
    name: "line3: no repeat of the same class after a correction",
    pass: classed.length > 0 && corrected.length === classed.length && repeats.length === 0,
    detail:
      `warned=${warned.length} classed=${classed.length} corrected=${corrected.length} repeats=${repeats.length}` +
      `${repeats.length > 0 ? ` first=${repeats[0]}` : ""}`,
    metrics: {
      warned: warned.length,
      classed: classed.length,
      corrected: corrected.length,
      repeats: repeats.length,
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
  const pairs: Array<{ sample: string; eventKind: string; latencyRatio: number; tokenRatio: number | null }> = [];
  for (const sample of lowRisk) {
    const b4 = postRows.find((row) => row.sample === sample.sample_id && row.baseline === "B4");
    const b4g = postRows.find((row) => row.sample === sample.sample_id && row.baseline === "B4g");
    if (!b4 || !b4g) continue;
    const latencyRatio = b4g.latency_ms === 0 ? Number.POSITIVE_INFINITY : b4.latency_ms / b4g.latency_ms;
    const t4 = tokensOf(b4);
    const t4g = tokensOf(b4g);
    pairs.push({
      sample: sample.sample_id,
      eventKind: sample.event_kind ?? "unknown",
      latencyRatio,
      tokenRatio: t4 !== null && t4g !== null && t4g !== 0 ? t4 / t4g : null,
    });
  }
  const medianLatency = median(pairs.map((pair) => pair.latencyRatio));
  const medianTokens = median(
    pairs.map((pair) => pair.tokenRatio).filter((value): value is number => value !== null),
  );
  const line4: LineResult = {
    name: "line4: B4 vs B4g paired token/latency ratios on 8 low-risk samples",
    pass: pairs.length === 8 && medianTokens !== null && medianTokens <= 1,
    detail:
      `pairs=${pairs.length} median_token_ratio=${medianTokens?.toFixed(3) ?? "na"} ` +
      `median_latency_ratio=${medianLatency?.toFixed(3) ?? "na"} ` +
      `available_pairs=${pairedCandidates.length}`,
    metrics: { pairs: pairs.length, median_token_ratio: medianTokens, median_latency_ratio: medianLatency },
  };

  const anchored = warned.filter(
    (row) =>
      typeof row.disposition.text === "string" &&
      row.disposition.text.includes("[CRS-WARN]") &&
      /CWE-\d+|\.\w{1,5}:\d+/.test(row.disposition.text),
  );
  const line5: LineResult = {
    name: "line5: correction anchor visible on the next request",
    pass: anchored.length > 0 && anchored.length === warned.length,
    detail: `warned=${warned.length} anchored=${anchored.length}`,
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
      ["line", "pass", "detail"],
      [line1, line2, line3, line4, line5].map((line) => [line.name, String(line.pass), line.detail]),
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
          String(n),
          `>= ${minSamples}`,
          recallGated ? "gated" : `insufficient_n (descriptive, not gated)`,
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
        pair.tokenRatio?.toFixed(3) ?? "na",
        pair.latencyRatio.toFixed(3),
      ]),
    ),
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

  const verdict = [
    `# 验收结论（${mode}）`,
    "",
    `五条线：${[line1, line2, line3, line4, line5].filter((line) => line.pass).length}/5 通过。`,
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
    ...(recallGated
      ? []
      : [
          "",
          `召回面 insufficient_n：recall=${recall.toFixed(3)}（${hits}/${n}）` +
            `${interval === null ? "" : `，Wilson 95% [${interval.low.toFixed(3)}, ${interval.high.toFixed(3)}]`}，` +
            "仅作描述性报告，不进门禁；“测不了”与“没测”是两回事。",
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

  return { mode, lines: [line1, line2, line3, line4, line5], resultsTable, verdict };
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
  const report = evaluateAcceptance(await loadRuns(resolve(runsDir)), await loadTruth(datasetDir), gaps, {
    coverage: { language: declared.language, perCwe: coverageCounts(declared) },
    frozenInstruments: pin,
  });
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "report.md"), `# 验收结果表（${report.mode}）\n\n${report.resultsTable}\n`, "utf8");
  await writeFile(join(outDir, "verdict.md"), report.verdict, "utf8");
  await writeFile(
    join(outDir, "verdict.json"),
    `${JSON.stringify(report.lines.map(({ name, pass, metrics }) => ({ name, pass, metrics })), null, 2)}\n`,
    "utf8",
  );
  process.stdout.write(`${report.lines.map((line) => `${line.pass ? "PASS" : "FAIL"} ${line.name}`).join("\n")}\n`);
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/acceptance.ts")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}

export type { ReviewRow, RunRecord };
