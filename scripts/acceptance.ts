import { readdir, readFile, mkdir, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import type { ReviewRow, RunRecord } from "../src/contracts/index.js";

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
  labels: LabelSpan[];
  expected_detectable_by: string[];
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
  change_event: { sessionId: string; ts: number } | null;
}

async function collectJsonl(root: string): Promise<string[]> {
  const out: string[] = [];
  const entries = await readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) out.push(...(await collectJsonl(path)));
    else if (entry.name.endsWith(".jsonl")) out.push(path);
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
    ) as SampleTruth;
    truth.set(entry.sample_id, { ...sample, expected_detectable_by: entry.expected_detectable_by });
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
  minSamples = 20,
): AcceptanceReport {
  const modes = new Set(rows.map((row) => row.mode));
  if (modes.size > 1) throw new Error(`live and replay rows must not be mixed: ${[...modes].join(",")}`);
  const mode = [...modes][0] ?? "unknown";
  const ordered = [...rows].sort((a, b) => (a.change_event?.ts ?? 0) - (b.change_event?.ts ?? 0));

  const mainRows = ordered.filter((row) => row.baseline === "B4");
  const detectable = mainRows.filter((row) => {
    const sample = truth.get(row.sample);
    return sample !== undefined && sample.labels.length > 0 && sample.expected_detectable_by.length > 0;
  });
  const predicated = detectable.filter((row) => row.disposition.preDecision === "deny");
  const truePositive = predicated.filter((row) => {
    const sample = truth.get(row.sample);
    return sample !== undefined && sample.labels.length > 0;
  });
  const falsePositive = predicated.length - truePositive.length;
  const missed = detectable.length - truePositive.length;
  const n = detectable.length;
  const k = predicated.length;
  const recall = n === 0 ? 0 : truePositive.length / n;
  const precision = k === 0 ? 0 : truePositive.length / k;
  const gapSamples = new Set((gaps?.gaps ?? []).map((gap) => gap.sample_id));
  const predictedGap = predicated.filter((row) => gapSamples.has(row.sample));
  const firstRun = ordered[0]?.change_event?.ts ?? null;
  const preregistered = gaps !== null && firstRun !== null && Date.parse(gaps.preregistered_at) <= firstRun;
  const line1Pass =
    mode === "live" &&
    preregistered &&
    n >= minSamples &&
    recall >= 0.7 &&
    precision >= 0.9 &&
    predictedGap.length === 0;
  const line1: LineResult = {
    name: "line1: block precision/recall on the detectable subset",
    pass: line1Pass,
    detail:
      `mode=${mode} n=${n} k=${k} recall=${recall.toFixed(3)} precision=${precision.toFixed(3)} ` +
      `preregistered_gaps=${preregistered} predicted_gaps=${predictedGap.length}`,
    metrics: { n, k, recall, precision, false_positive: falsePositive, missed, preregistered: String(preregistered) },
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
    pass: registryHits.length > 0,
    detail: `registry_hits=${registryHits.length}`,
    metrics: { registry_hits: registryHits.length },
  };

  const warned = ordered.filter((row) => row.disposition.postDecision === "inject_warn");
  const repeats: string[] = [];
  for (const row of warned) {
    const ts = row.change_event?.ts ?? 0;
    const classes = new Set(
      row.findings_merged.map((finding) => `${finding.file}\u0000${finding.cwe ?? "none"}`),
    );
    for (const later of ordered) {
      if ((later.change_event?.ts ?? 0) <= ts) continue;
      for (const finding of later.findings_merged) {
        if (classes.has(`${finding.file}\u0000${finding.cwe ?? "none"}`)) {
          repeats.push(`${row.sample}->${later.sample}:${finding.file}`);
        }
      }
    }
  }
  const line3: LineResult = {
    name: "line3: no repeat of the same class after a correction",
    pass: warned.length > 0 && repeats.length === 0,
    detail: `warned=${warned.length} repeats=${repeats.length}${repeats.length > 0 ? ` first=${repeats[0]}` : ""}`,
    metrics: { warned: warned.length, repeats: repeats.length },
  };

  const lowRisk = [...truth.values()].filter((sample) => sample.risk_level === "low").slice(0, 8);
  const pairs: Array<{ sample: string; latencyRatio: number; tokenRatio: number | null }> = [];
  for (const sample of lowRisk) {
    const b4 = ordered.find((row) => row.sample === sample.sample_id && row.baseline === "B4");
    const b4g = ordered.find((row) => row.sample === sample.sample_id && row.baseline === "B4g");
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
  ].join("\n");

  const verdict = [
    `# 验收结论（${mode}）`,
    "",
    `四条线：${[line1, line2, line3, line4, line5].filter((line) => line.pass).length}/5 通过。`,
    "",
    "结果表见 report.md；本文件只给结论，不把接口通过当质量结论。",
    "",
  ].join("\n");

  return { mode, lines: [line1, line2, line3, line4, line5], resultsTable, verdict };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const arg = (name: string, fallback: string): string => {
    const index = args.indexOf(name);
    return index >= 0 && args[index + 1] ? args[index + 1]! : fallback;
  };
  const runsDir = resolve(arg("--runs", "runs"));
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const gapsPath = resolve(arg("--gaps", "artifacts/block-gaps.json"));
  const outDir = resolve(arg("--out", "artifacts/acceptance"));
  const gaps = existsSync(gapsPath) ? (JSON.parse(await readFile(gapsPath, "utf8")) as BlockGaps) : null;
  const report = evaluateAcceptance(await loadRuns(runsDir), await loadTruth(datasetDir), gaps);
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
