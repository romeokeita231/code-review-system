import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { ReviewRow, RunRecord } from "../src/contracts/index.js";
import { coverageCounts, cweKey, declaredCoverage, loadRulesTable } from "./coverage.js";
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
  /** Absent means "coverage unknown" - then every labelled eval sample counts. */
  coverage?: RuleCoverage;
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
  sources: Array<{ source: string; status: string; findings: Array<{ file: string; cwe: string | null; evidence: string | null }> }>;
  tokens: { total: number | null } | number | null;
  latency_ms: number;
  change_event: { sessionId: string; ts: number; phase?: string } | null;
}

export async function collectJsonl(root: string): Promise<string[]> {  const out: string[] = [];
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) out.push(...(await collectJsonl(path)));
    else if (entry.name.endsWith(".jsonl") && !entry.name.startsWith("pairing")) out.push(path);
  }
  return out;
}

export async function loadRuns(root: string): Promise<AcceptanceRowLike[]> {
  const rows: AcceptanceRowLike[] = [];
  for (const file of await collectJsonl(root)) {
    for (const line of (await readFile(file, "utf8")).split("\n")) {
      if (line.trim().length === 0) continue;
      rows.push(JSON.parse(line) as AcceptanceRowLike);
    }
  }
  return rows;
}

export async function loadTruth(datasetDir: string): Promise<Map<string, SampleTruth>> {
  const manifest = JSON.parse(await readFile(join(datasetDir, "manifest.json"), "utf8")) as {
    samples: Array<{ sample_id: string; split: string; risk_level: string; paired_safe: boolean; expected_detectable_by: string[] }>;
  };
  const truth = new Map<string, SampleTruth>();
  for (const entry of manifest.samples) {
    const sample = JSON.parse(
      await readFile(join(datasetDir, "samples", `${entry.sample_id}.json`), "utf8"),
    ) as Omit<SampleTruth, "sample_cwe"> & { cwe: string | null };
    truth.set(entry.sample_id, {
      ...sample,
      sample_cwe: sample.cwe,
      expected_detectable_by: entry.expected_detectable_by,
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
  const coverage = options.coverage;
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
  // `expected_detectable_by` is a non-truth hint (annotation spec §6) and must
  // not select the denominator. The ruleset's *declared* coverage does, and it
  // is a fact about the pinned rules table, decidable before unblinding.
  const covered = (row: AcceptanceRowLike): boolean => {
    if (coverage === undefined) return true;
    const key = cweKey(truth.get(row.sample)?.sample_cwe ?? null);
    return key !== null && (coverage.perCwe[key] ?? 0) > 0;
  };
  const positives = evalPositives.filter(covered);
  const excluded = evalPositives.filter((row) => !covered(row));
  const negatives = mainRows.filter((row) => {
    const sample = truth.get(row.sample);
    return sample !== undefined && sample.labels.length === 0;
  });
  const denied = (row: AcceptanceRowLike): boolean => row.disposition.preDecision === "deny";
  const truePositive = positives.filter(denied);
  const falsePositive = negatives.filter(denied);
  const missed = positives.length - truePositive.length;
  const n = positives.length;
  const k = truePositive.length + falsePositive.length;
  const recall = n === 0 ? 0 : truePositive.length / n;
  // With no defect-free row in the run there is no false-positive denominator,
  // and `tp / tp` would report a perfect 1.0 precision that measured nothing.
  const precisionMeasurable = negatives.length > 0;
  const precision = !precisionMeasurable || k === 0 ? 0 : truePositive.length / k;
  const gapSamples = new Set((gaps?.gaps ?? []).map((gap) => gap.sample_id));
  const predictedGap = mainRows.filter((row) => denied(row) && gapSamples.has(row.sample));
  const firstRun = ordered[0]?.change_event?.ts ?? null;
  const preregistered = gaps !== null && firstRun !== null && Date.parse(gaps.preregistered_at) <= firstRun;
  const line1Pass =
    mode === "live" &&
    preregistered &&
    n >= minSamples &&
    precisionMeasurable &&
    recall >= 0.7 &&
    precision >= 0.9 &&
    predictedGap.length === 0;
  const excludedClasses = [...new Set(excluded.map((row) => cweKey(truth.get(row.sample)?.sample_cwe ?? null) ?? "none"))];
  const line1: LineResult = {
    name: "line1: block precision/recall on the covered eval positives",
    pass: line1Pass,
    detail:
      `mode=${mode} n=${n} k=${k} recall=${recall.toFixed(3)} ` +
      `precision=${precisionMeasurable ? precision.toFixed(3) : "na"} negatives=${negatives.length} ` +
      `excluded=${excluded.length}${excludedClasses.length > 0 ? `(${excludedClasses.join(",")})` : ""} ` +
      `preregistered_gaps=${preregistered} predicted_gaps=${predictedGap.length}`,
    metrics: {
      n,
      k,
      recall,
      precision: precisionMeasurable ? precision : null,
      false_positive: falsePositive.length,
      negatives: negatives.length,
      missed,
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

  const lowRisk = [...truth.values()].filter((sample) => sample.risk_level === "low").slice(0, 8);
  const pairs: Array<{ sample: string; latencyRatio: number; tokenRatio: number | null }> = [];
  for (const sample of lowRisk) {
    const b4 = postRows.find((row) => row.sample === sample.sample_id && row.baseline === "B4");
    const b4g = postRows.find((row) => row.sample === sample.sample_id && row.baseline === "B4g");
    if (!b4 || !b4g) continue;
    const latencyRatio = b4g.latency_ms === 0 ? Number.POSITIVE_INFINITY : b4.latency_ms / b4g.latency_ms;
    const t4 = tokensOf(b4);
    const t4g = tokensOf(b4g);
    pairs.push({
      sample: sample.sample_id,
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
      `median_latency_ratio=${medianLatency?.toFixed(3) ?? "na"}`,
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
    table(
      ["line", "pass", "detail"],
      [line1, line2, line3, line4, line5].map((line) => [line.name, String(line.pass), line.detail]),
    ),
    "",
    table(
      ["sample", "B4/B4g token ratio", "B4/B4g latency ratio"],
      pairs.map((pair) => [pair.sample, pair.tokenRatio?.toFixed(3) ?? "na", pair.latencyRatio.toFixed(3)]),
    ),
    ...(coverageRows.length > 0
      ? [
          "",
          `line1 denominator by class (declared ${coverage?.language ?? "?"} rules):`,
          "",
          table(["class", "declared rules", "eval rows", "outside line1"], coverageRows),
        ]
      : []),
  ].join("\n");

  const verdict = [
    `# 验收结论（${mode}）`,
    "",
    `五条线：${[line1, line2, line3, line4, line5].filter((line) => line.pass).length}/5 通过。`,
    "",
    "结果表见 report.md；本文件只给结论，不把接口通过当质量结论。",
    ...(coverage === undefined
      ? []
      : [
          "",
          `line1 分母口径：按钉定规则表声明的 ${coverage.language} 规则分面，` +
            `${excluded.length} 条 eval 正样本因规则集无该类规则不在分母内（见结果表末表）。`,
        ]),
    "",
  ].join("\n");

  return { mode, lines: [line1, line2, line3, line4, line5], resultsTable, verdict };
}

async function main(): Promise<void> {
  const runsDir = resolve(arg("--runs", "runs"));
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const gapsPath = resolve(arg("--gaps", "artifacts/block-gaps.json"));
  const outDir = resolve(arg("--out", "artifacts/acceptance"));
  const rulesPath = resolve(arg("--rules", "research/semgrep-bench/snapshot/rules_table.json"));
  const declared = declaredCoverage(loadRulesTable(rulesPath), arg("--language", "ts"));
  const gaps = existsSync(gapsPath) ? (JSON.parse(await readFile(gapsPath, "utf8")) as BlockGaps) : null;
  const report = evaluateAcceptance(await loadRuns(runsDir), await loadTruth(datasetDir), gaps, {
    coverage: { language: declared.language, perCwe: coverageCounts(declared) },
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
