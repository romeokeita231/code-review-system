import { readFile, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { configHash } from "../config/index.js";
import {
  DatasetManifest,
  type AnnotationSample,
  type Baseline,
  type CalibrationArtifact,
  type ChangeEvent,
  type Disposition,
  type MergedFinding,
  type Mode,
  type PairingRow,
  type RunConfig,
  type RunRecord,
  type SignalSource,
  type SourceName,
  type SourceResult,
  type Toolchain,
} from "../contracts/index.js";
import { review } from "../l2/index.js";
import { readJsonl, writeJsonl } from "./jsonl.js";
import { pair, type GtSpan } from "./pairing.js";
import {
  loadRecorded,
  missingRecording,
  RecordedSource,
  type RecordedBySample,
} from "./recorded.js";

export interface LabelSpan {
  path: string;
  startLine: number;
  endLine: number;
  cwe: string | null;
}

export interface DatasetSample extends AnnotationSample {
  before: string;
  after: string;
  labels: LabelSpan[];
}

export interface LoadedDataset {
  manifest: DatasetManifest;
  samples: DatasetSample[];
}

export const LADDER: Baseline[] = ["B0", "B1", "B2", "B3", "B4g", "B4"];

/**
 * Label spans for a sample file.
 *
 * The self-built set stores them as `defects[]` (`line_start`/`line_end`), the
 * imported sets store them as `labels[]`. Both project onto the same span the
 * replay layer scores against, so a row is never scored on a field it does not
 * carry.
 */
function labelsOf(file: Record<string, unknown>): LabelSpan[] {
  const defects = file["defects"];
  if (Array.isArray(defects)) {
    return defects.map((defect) => {
      const row = (typeof defect === "object" && defect !== null ? defect : {}) as Record<string, unknown>;
      return {
        path: String(row["file"] ?? ""),
        startLine: Number(row["line_start"] ?? 0),
        endLine: Number(row["line_end"] ?? 0),
        cwe: row["cwe"] === null || row["cwe"] === undefined ? null : String(row["cwe"]),
      };
    });
  }
  const labels = file["labels"];
  return Array.isArray(labels) ? (labels as LabelSpan[]) : [];
}

export async function loadDataset(dir: string): Promise<LoadedDataset> {
  const manifest = DatasetManifest.parse(
    JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")),
  );
  const samples: DatasetSample[] = [];
  for (const entry of manifest.samples) {
    const raw = JSON.parse(
      await readFile(join(dir, "samples", `${entry.sample_id}.json`), "utf8"),
    ) as Record<string, unknown>;
    if (raw["sample_id"] !== entry.sample_id) {
      throw new Error(`sample id mismatch for ${entry.sample_id}: ${String(raw["sample_id"])}`);
    }
    samples.push({
      ...entry,
      before: String(raw["before"] ?? ""),
      after: String(raw["after"] ?? ""),
      labels: labelsOf(raw),
    });
  }
  return { manifest, samples };
}

export function sourceNamesFor(baseline: Baseline): SourceName[] {
  switch (baseline) {
    case "B0":
      return [];
    case "B1":
    case "single":
      return ["semgrep"];
    case "B2":
      return ["aor"];
    default:
      return ["semgrep", "aor"];
  }
}

export function effectiveConfig(config: RunConfig, baseline: Baseline, mode: Mode = "replay"): RunConfig {
  const clone = structuredClone(config);
  clone.mode = mode;
  clone.baseline = baseline;
  const names = sourceNamesFor(baseline);
  clone.sources.semgrep.enabled = names.includes("semgrep");
  clone.sources.aor.enabled = names.includes("aor");
  if (baseline === "B1" || baseline === "B2" || baseline === "B3") {
    clone.fusionStages = { merge: false, conflict: false, calibrate: false, vote: false };
  }
  if (baseline === "B4g" || baseline === "B1" || baseline === "B2" || baseline === "B3" || baseline === "B0") {
    clone.triage.enabled = false;
  }
  if (baseline === "B4") clone.triage.enabled = true;
  if (baseline === "single") clone.triage.enabled = false;
  return clone;
}

export function effectiveConfigHash(config: RunConfig, baseline: Baseline, mode: Mode = "replay"): string {
  return configHash(effectiveConfig(config, baseline, mode));
}

function toolchainOf(config: RunConfig): Toolchain {
  return {
    semgrep: config.sources.semgrep.version,
    aor: config.sources.aor.versionCommit,
    crg: config.sources.crg.command,
    node: process.version,
    platform: process.platform,
  };
}

export function changeEventOf(sample: DatasetSample): ChangeEvent {
  return {
    id: `replay:${sample.sample_id}`,
    sessionId: "replay",
    rootCallId: sample.sample_id,
    phase: "post",
    trigger: "write",
    files: [sample.path],
    diff: null,
    diffProvenance: "observed",
    ts: 0,
  };
}

function outcomeOf(disposition: Disposition, status: RunRecord["status"]): RunRecord["outcome"] {
  if (status === "skipped") return "none";
  if (disposition.preDecision === "deny") return "block";
  if (disposition.postDecision === "inject_warn") return "warn";
  if (disposition.finalDisposition === "record") return "record";
  return "none";
}

function b0Disposition(sample: DatasetSample, tier: 0 = 0): Disposition {
  return {
    mechanism: "record",
    findings: [],
    text: null,
    pSemgrep: null,
    pFused: null,
    preDecision: "not_run",
    postDecision: "not_run",
    finalDisposition: "record",
    reviewStatus: "skipped",
    skipReason: "no_change",
    blockLoop: false,
    tier,
    tierSource: "none",
    gate: { perFileTier: { [sample.path]: tier } },
  };
}

function anonymousRecord(
  options: {
    runId: string;
    sample: DatasetSample;
    baseline: Baseline;
    mode: Mode;
    hash: string;
    repeat: number;
    toolchain: Toolchain;
    repoRev: string;
    filesScanned: number;
    cache: "cold" | "warm" | null;
  },
  disposition: Disposition,
  status: RunRecord["status"],
  error: string | null,
): RunRecord {
  return {
    run_id: options.runId,
    sample: options.sample.sample_id,
    tier: disposition.tier,
    repeat: options.repeat,
    mode: options.mode,
    baseline: options.baseline,
    config_hash: options.hash,
    change_event: changeEventOf(options.sample),
    findings_merged: [],
    findings_raw_ref: `raw/${options.runId}.json`,
    sources: [],
    disposition,
    gate: disposition.gate,
    tokens: { total: null, input: null, output: null, cache_read: null, cache_write: null },
    latency_ms: 0,
    status,
    outcome: "none",
    error,
    toolchain: options.toolchain,
    repo: { rev: options.repoRev, files_scanned: options.filesScanned },
    cache: options.cache,
  };
}

export interface RunBaselineOptions {
  baseline: Baseline;
  mode?: Mode;
  config: RunConfig;
  samples: readonly DatasetSample[];
  recordedDir: string;
  runId: string;
  datasetRoot?: string;
  recorded?: RecordedBySample;
  repeat?: number;
  cache?: "cold" | "warm" | null;
  artifact?: CalibrationArtifact | null;
  toolchain?: Toolchain;
  repoRev?: string;
  filesScanned?: number;
  outDir?: string;
}

export interface PersistedRunFile {
  path: string;
  hash: string;
}

function tokenTotals(sources: readonly SourceResult[]): RunRecord["tokens"] {
  const pick = (key: "total" | "input" | "output" | "cacheRead" | "cacheWrite"): number | null => {
    const values = sources
      .map((source) => source.tokenDetail?.[key])
      .filter((value): value is number => typeof value === "number");
    return values.length === 0 ? null : values.reduce((sum, value) => sum + value, 0);
  };
  const detailTotal = pick("total");
  const fallback = sources
    .map((source) => source.tokens)
    .filter((value): value is number => typeof value === "number");
  return {
    total:
      detailTotal !== null
        ? detailTotal
        : fallback.length === 0
          ? null
          : fallback.reduce((sum, value) => sum + value, 0),
    input: pick("input"),
    output: pick("output"),
    cache_read: pick("cacheRead"),
    cache_write: pick("cacheWrite"),
  };
}

export async function persistRunRecords(
  outDir: string,
  runId: string,
  hash: string,
  records: readonly RunRecord[],
): Promise<PersistedRunFile> {
  const path = join(outDir, "runs", runId, `runs.${hash}.jsonl`);
  let existing: RunRecord[] = [];
  try {
    existing = await readJsonl<RunRecord>(path);
  } catch {
    existing = [];
  }
  for (const row of existing) {
    if (row.config_hash !== hash) {
      throw new Error(`config hash mismatch in ${path}: ${row.config_hash} != ${hash}`);
    }
  }
  for (const row of records) {
    if (row.config_hash !== hash) {
      throw new Error(`config hash mismatch in memory for ${row.sample}: ${row.config_hash} != ${hash}`);
    }
  }
  await writeJsonl(path, records);
  return { path, hash };
}

export async function runBaseline(opts: RunBaselineOptions): Promise<RunRecord[]> {
  const mode: Mode = opts.mode ?? "replay";
  const config = effectiveConfig(opts.config, opts.baseline, mode);
  const hash = configHash(config);
  const toolchain = opts.toolchain ?? toolchainOf(config);
  const repeat = opts.repeat ?? 0;
  const filesScanned = opts.filesScanned ?? opts.samples.length;
  const repoRev = opts.repoRev ?? opts.datasetRoot ?? "replay";
  const cache = opts.cache === undefined ? "cold" : opts.cache;
  const recorded = opts.recorded ?? (await loadRecorded(opts.recordedDir));

  if (opts.baseline === "B0") {
    const records = opts.samples.map((sample) =>
      anonymousRecord(
        {
          runId: opts.runId,
          sample,
          baseline: "B0",
          mode,
          hash,
          repeat,
          toolchain,
          repoRev,
          filesScanned,
          cache,
        },
        b0Disposition(sample),
        "skipped",
        "B0 not applicable in replay",
      ),
    );
    if (opts.outDir) await persistRunRecords(opts.outDir, opts.runId, hash, records);
    return records;
  }

  const names = sourceNamesFor(opts.baseline);
  const records: RunRecord[] = [];
  for (const sample of opts.samples) {
    const available: SourceResult[] = recorded[sample.sample_id] ?? [];
    const sources: SignalSource[] = names.map((name) => {
      const result = available.find((entry) => entry.source === name) ?? missingRecording(name);
      return new RecordedSource(result);
    });
    const outcome = await review(changeEventOf(sample), {
      runId: opts.runId,
      config,
      sources,
      artifact: opts.artifact ?? null,
      toolchain,
      sourceText: { [sample.path]: sample.after },
    });
    const row = outcome.row;
    const status = row.status;
    const disposition = outcome.disposition;
    const tokens = tokenTotals(row.sources);
    const record: RunRecord = {
      run_id: row.run_id,
      sample: sample.sample_id,
      tier: row.tier,
      repeat,
      mode,
      baseline: opts.baseline,
      config_hash: row.config_hash,
      change_event: row.change_event,
      findings_merged: row.findings_merged,
      findings_raw_ref: `raw/${opts.runId}.json`,
      sources: row.sources,
      disposition,
      gate: row.gate,
      tokens,
      latency_ms: row.latency_ms,
      status,
      outcome: outcomeOf(disposition, status),
      error: status === "ok" ? null : row.review_skip_reason,
      toolchain,
      repo: { rev: repoRev, files_scanned: filesScanned },
      cache:
        tokens.cache_read === null
          ? cache
          : tokens.cache_read > 0
            ? "warm"
            : "cold",
    };
    if (record.config_hash !== hash) {
      throw new Error(`config hash drift for ${sample.sample_id}: ${record.config_hash} != ${hash}`);
    }
    records.push(record);
  }

  if (opts.outDir) await persistRunRecords(opts.outDir, opts.runId, hash, records);
  return records;
}

export interface RunReplayOptions {
  config: RunConfig;
  samples?: readonly DatasetSample[];
  datasetDir?: string;
  recordedDir?: string;
  runId?: string;
  runIdPrefix?: string;
  outDir: string;
  datasetRoot?: string;
  baselines?: Baseline[];
  mode?: Mode;
  repeat?: number;
  repeats?: number;
  cache?: "cold" | "warm" | null;
  artifact?: CalibrationArtifact | null;
  toolchain?: Toolchain;
  repoRev?: string;
  filesScanned?: number;
}

export interface ReplayResult {
  runs: RunRecord[];
  pairing: PairingRow[];
  hashes: string[];
  dir: string;
}

function gtSpansOf(sample: DatasetSample): GtSpan[] {
  return sample.labels.map((label, index) => ({
    id: `${sample.sample_id}:${index}`,
    path: label.path,
    startLine: label.startLine,
    endLine: label.endLine,
    cwe: label.cwe,
  }));
}

export async function runReplay(opts: RunReplayOptions): Promise<ReplayResult> {
  const mode: Mode = opts.mode ?? "replay";
  const baselines = opts.baselines ?? LADDER;
  const samples = opts.samples ?? (opts.datasetDir ? (await loadDataset(opts.datasetDir)).samples : null);
  if (!samples) throw new Error("runReplay requires samples or datasetDir");
  const datasetDir = opts.datasetDir ?? opts.datasetRoot;
  if (!datasetDir) throw new Error("runReplay requires datasetDir");
  const recordedDir = opts.recordedDir ?? join(datasetDir, "recorded");
  const runIdBase = opts.runId ?? opts.runIdPrefix ?? "replay";
  const recorded = await loadRecorded(recordedDir);
  const rootDir = join(opts.outDir, "runs", runIdBase);
  const allRuns: RunRecord[] = [];
  const allPairing: PairingRow[] = [];
  const hashes: string[] = [];

  for (const baseline of baselines) {
    const runId = `${runIdBase}-${baseline}`;
    const config = effectiveConfig(opts.config, baseline, mode);
    const hash = configHash(config);
    hashes.push(hash);
    const repeats = Math.max(1, opts.repeats ?? 1);
    const records: RunRecord[] = [];
    for (let index = 0; index < repeats; index += 1) {
      records.push(
        ...(await runBaseline({
          baseline,
          mode,
          config: opts.config,
          samples,
          recordedDir,
          recorded,
          runId,
          datasetRoot: datasetDir,
          repeat: index,
          cache: repeats > 1 ? (index === 0 ? "cold" : "warm") : opts.cache,
          artifact: opts.artifact,
          toolchain: opts.toolchain,
          repoRev: opts.repoRev,
          filesScanned: opts.filesScanned,
        })),
      );
    }
    allRuns.push(...records);

    const baselineDir = join(rootDir, baseline);
    await mkdir(baselineDir, { recursive: true });
    await writeJsonl(join(baselineDir, `runs.${hash}.jsonl`), records);
    await writeFile(
      join(baselineDir, "config.json"),
      `${JSON.stringify({ config_hash: hash, config }, null, 2)}\n`,
      "utf8",
    );
    const raw: Record<string, SourceResult[]> = {};
    for (const record of records) raw[record.sample] = record.sources;
    await mkdir(join(baselineDir, "raw"), { recursive: true });
    await writeFile(
      join(baselineDir, "raw", `${runId}.json`),
      `${JSON.stringify(raw, null, 2)}\n`,
      "utf8",
    );

    for (const record of records) {
      const sample = samples.find((entry) => entry.sample_id === record.sample);
      if (!sample) continue;
      const rows = pair(runId, gtSpansOf(sample), record.findings_merged as MergedFinding[]);
      allPairing.push(...rows);
    }
  }

  await writeJsonl(join(rootDir, "runs.jsonl"), allRuns);
  await writeJsonl(join(rootDir, "pairing.jsonl"), allPairing);
  return { runs: allRuns, pairing: allPairing, hashes, dir: rootDir };
}
