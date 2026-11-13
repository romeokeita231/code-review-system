import { execa } from "execa";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import type { Baseline, ChangeEvent, Mode, ReviewRow, RunConfig, Tier } from "../src/contracts/index.js";
import { calibrationCategories, DatasetManifest } from "../src/contracts/index.js";
import {
  assertBudgetRelations,
  assertCalibrationMatches,
  loadCalibration,
  sha256,
  TOOL_ENV,
} from "../src/config/index.js";
import { computeTier, configuredModelOf, parseAorProbe } from "../src/l2/index.js";
import { createCrgTriage } from "../src/l3/index.js";
import { synthesizeDiff } from "../src/l1/events.js";
import { labelsOf, loadDataset, type DatasetSample } from "../src/l5/replay.js";
import { evaluateAcceptance, loadTruth, type AcceptanceRowLike, type FrozenInstruments, type RuleCoverage } from "./acceptance.js";
import { arg } from "./shared.js";
import {
  coverageCounts,
  cweKey,
  declaredCoverage,
  loadRulesTable,
  rulesFor,
  semgrepLanguage,
} from "./coverage.js";

export interface PlannedSample {
  sampleId: string;
  /** Ground-truth class, kept so reports can stratify per CWE. */
  cwe: string | null;
  /** Repo-relative POSIX path, as the plugin records it. */
  path: string;
  /** Staged text the agent copies verbatim. */
  staged: string;
  kind: "positive" | "low-risk" | "control" | "dep-probe";
  /** `edit` or `create`; derived from the dataset row, never chosen here. */
  eventKind: "edit" | "create";
}

export interface CoveragePlan {
  /** Rules table the declaration was read from. */
  table: string;
  language: string;
  /** CWE key -> number of rules declaring it for that language. */
  declared: Record<string, number>;
  /**
   * Eval positives whose class the ruleset declares no rule for. They are
   * outside the recall denominator by construction and are listed here so the
   * exclusion is auditable instead of a silent slice.
   */
  uncovered: Array<{ sampleId: string; cwe: string | null }>;
}

export interface DrillPlan {
  positives: PlannedSample[];
  lowRisk: PlannedSample[];
  /**
   * Defect-free rows staged as line 1's false-positive denominator. Separate
   * from `lowRisk`, which exists for line 4's B4/B4g pairing.
   */
  controls: PlannedSample[];
  probe: PlannedSample;
  coverage: CoveragePlan;
  /** `ds-2.0.0` and friends: the run directory is keyed by this. */
  datasetVersion: string;
  warnings: string[];
}

/** Every class gets at most this many positives, so one class cannot dominate. */
export const POSITIVE_CAP_PER_CLASS = 4;
export const RULES_TABLE = "research/semgrep-bench/snapshot/rules_table.json";

export const DEP_PROBE: PlannedSample = {
  sampleId: "dep-hallucination-01",
  cwe: null,
  path: "live/dep-hallucination-01/package.json",
  staged: ".staging/dep-hallucination-01.txt",
  kind: "dep-probe",
  // The probe writes a new package.json into a repo that has none.
  eventKind: "create",
};

const DEP_PROBE_BODY = `{
  "name": "crs-live-dep-probe",
  "private": true,
  "dependencies": {
    "crs-no-such-package-xyz-2026": "^1.0.0"
  }
}
`;

function stagedOf(sample: DatasetSample): string {
  return `.staging/${sample.sample_id.replace(/[\\/:*?"<>|]/g, "_")}.txt`;
}

function livePath(sample: DatasetSample): string {
  // Several dataset samples share one source path (a vulnerable file and its
  // paired safe variant). The live drill needs one distinct file per sample so
  // each write is attributable, so every sample gets its own directory.
  const parts = sample.path.replace(/\\/g, "/").split("/");
  const name = parts[parts.length - 1] ?? "sample.ts";
  return `live/${sample.sample_id}/${name}`;
}

export interface PlanOptions {
  limitPositives?: number;
  lowRiskCount?: number;
  controlCount?: number;
  rulesTablePath?: string;
  /** Stage only this language; default is the one the eval positives use. */
  language?: string;
}

const hashOf = (sampleId: string): string => createHash("sha256").update(sampleId, "utf8").digest("hex");

/**
 * The live set is the spec's 20 injection positives plus 8 defect-free low-risk
 * samples and one dependency-hallucination probe.
 *
 * Positive selection is deliberately *not* driven by `expected_detectable_by`:
 * the annotation spec (鎼?) marks that field as a non-truth hint that must not
 * enter any metric, and using it as the selector let the dataset define its own
 * denominator. The subset is instead decided before unblinding by a mechanical
 * fact - whether the frozen rules table declares a rule for the sample's class
 * and language - and sampling is deterministic: `sha256(sample_id)` ordering
 * (no `localeCompare`, which clusters by class prefix), round-robin across
 * classes, at most `POSITIVE_CAP_PER_CLASS` per class.
 *
 * Samples outside the declared coverage are returned in `coverage.uncovered`
 * so a report can print them as an explicit "not in the denominator" row.
 */
export function planDrill(datasetDir: string, options: PlanOptions = {}): DrillPlan {
  const limitPositives = options.limitPositives ?? 20;
  // No cap by default: the low-risk pool *is* line 1's false-positive
  // denominator, and a cap would silently drop a create row out of it.
  const lowRiskCount = options.lowRiskCount ?? Number.POSITIVE_INFINITY;
  const controlCount = options.controlCount ?? 8;
  const tablePath = options.rulesTablePath ?? RULES_TABLE;
  const loaded = loadDatasetSync(datasetDir, options.language);
  const coverage = declaredCoverage(loadRulesTable(tablePath), loaded.language);

  const candidates = loaded.samples
    .filter((sample) => sample.split === "eval" && sample.labels.length > 0)
    .sort((a, b) => hashOf(a.sample_id).localeCompare(hashOf(b.sample_id)));

  const byClass = new Map<string, DatasetSample[]>();
  for (const sample of candidates) {
    const key = cweKey(sample.cwe) ?? "none";
    const bucket = byClass.get(key) ?? [];
    bucket.push(sample);
    byClass.set(key, bucket);
  }

  const uncovered: CoveragePlan["uncovered"] = [];
  const queues: Array<{ key: string; items: DatasetSample[] }> = [];
  for (const [key, items] of byClass) {
    if (rulesFor(coverage, items[0]!.cwe).length === 0) {
      for (const item of items) uncovered.push({ sampleId: item.sample_id, cwe: item.cwe });
      continue;
    }
    queues.push({ key, items: [...items] });
  }
  // Every eval positive the ruleset could see: the denominator line 1 *could*
  // have had, before the per-class cap trimmed the staged set.
  const gateable = queues.reduce((sum, queue) => sum + queue.items.length, 0);

  const taken = new Map<string, number>();
  const picked: DatasetSample[] = [];
  let progressed = true;
  while (picked.length < limitPositives && progressed) {
    progressed = false;
    for (const queue of queues) {
      if (picked.length >= limitPositives) break;
      const used = taken.get(queue.key) ?? 0;
      if (used >= POSITIVE_CAP_PER_CLASS) continue;
      const next = queue.items.shift();
      if (next === undefined) continue;
      taken.set(queue.key, used + 1);
      picked.push(next);
      progressed = true;
    }
  }

  const positives = picked.map((sample) => ({
    sampleId: sample.sample_id,
    cwe: sample.cwe,
    path: livePath(sample),
    staged: stagedOf(sample),
    kind: "positive" as const,
    eventKind: sample.event_kind,
  }));
  const chosen = new Set(positives.map((sample) => sample.sampleId));

  // Line 4 pairs B4 against B4g on low-risk samples, and line 1 needs a
  // defect-free denominator; since the negatives are small safe edits they are
  // `low` risk as well, so one pool serves both lines. Only defect-free rows are
  // staged: a defective low-risk row would either inflate precision or put a
  // vulnerable file into line 4's pairs.
  const spare = loaded.samples
    .filter((sample) => sample.risk_level === "low" && !chosen.has(sample.sample_id))
    .sort((a, b) => hashOf(a.sample_id).localeCompare(hashOf(b.sample_id)));
  const defectFree = spare.filter((sample) => sample.labels.length === 0);
  const lowRiskPicks = defectFree.slice(0, lowRiskCount);
  const lowRisk = lowRiskPicks.map((sample) => ({
    sampleId: sample.sample_id,
    cwe: sample.cwe,
    path: livePath(sample),
    staged: stagedOf(sample),
    kind: "low-risk" as const,
    eventKind: sample.event_kind,
  }));

  // Defect-free rows that the low-risk pool did not take. A create sample that
  // is deliberately larger than 30 lines is defect-free but no longer `low`
  // risk, so it lands here: staged and exercised, outside line 4's pair pool
  // (which `evaluateAcceptance` rebuilds from the ground truth, not from this
  // list).
  const stagedControlIds = new Set(lowRisk.map((sample) => sample.sampleId));
  const controls = loaded.samples
    .filter((sample) => sample.labels.length === 0 && !chosen.has(sample.sample_id))
    .filter((sample) => !stagedControlIds.has(sample.sample_id))
    .sort((a, b) => hashOf(a.sample_id).localeCompare(hashOf(b.sample_id)))
    .slice(0, controlCount)
    .map((sample) => ({
      sampleId: sample.sample_id,
      cwe: sample.cwe,
      path: livePath(sample),
      staged: stagedOf(sample),
      kind: "control" as const,
      eventKind: sample.event_kind,
    }));
  const defectFreeStaged =
    lowRiskPicks.filter((sample) => sample.labels.length === 0).length + controls.length;

  const warnings: string[] = [];
  if (loaded.skipped > 0) {
    warnings.push(
      `${loaded.skipped} rows in another language sit outside this drill (staged language: ${loaded.language})`,
    );
  }
  if (positives.length < limitPositives) {
    warnings.push(
      `only ${positives.length} of ${gateable} gateable eval positives staged (wanted ${limitPositives}): ` +
        `${queues.length} classes with declared ${coverage.language} rules, ` +
        `${POSITIVE_CAP_PER_CLASS} per class cap, ${uncovered.length} samples outside coverage`,
    );
  }
  if (uncovered.length > 0) {
    const classes = [...new Set(uncovered.map((sample) => sample.cwe ?? "null"))].join(",");
    warnings.push(
      `${uncovered.length} eval positives sit outside the recall denominator ` +
        `(no declared ${coverage.language} rule for ${classes})`,
    );
  }
  if (Number.isFinite(lowRiskCount) && lowRisk.length < lowRiskCount) {
    warnings.push(
      `only ${lowRisk.length} low-risk samples available (${lowRiskCount} wanted for line4's B4/B4g pairs)`,
    );
  }
  if (spare.length > defectFree.length) {
    warnings.push(
      `${spare.length - defectFree.length} low-risk rows carry a defect and stay out of the pool: ` +
        `line 1 needs a defect-free denominator and line 4 needs defect-free pairs`,
    );
  }
  if (defectFreeStaged === 0) {
    warnings.push("no defect-free row staged: line1 precision has no false-positive denominator");
  }

  return {
    positives,
    lowRisk,
    controls,
    probe: { ...DEP_PROBE },
    coverage: {
      table: tablePath,
      language: coverage.language,
      declared: coverageCounts(coverage),
      uncovered,
    },
    datasetVersion: loaded.version,
    warnings,
  };
}

export interface LoadedDataset {
  language: string;
  /** Dataset identity the run must be checked against; empty when unreadable. */
  version: string;
  samples: DatasetSample[];
  /** Rows in another language, kept out of the drill and reported. */
  skipped: number;
}

/** Defect spans: `defects[]` on the self set, `labels[]` on the imported ones. */
function loadDatasetSync(datasetDir: string, requestedLanguage?: string): LoadedDataset {
  // loadDataset is async; the plan is pure so callers can plan before any
  // staging. Keep one synchronous read path for determinism, but read the
  // manifest through its schema: a hand-written shape let the plan decide on a
  // field the rest of the system spelled differently.
  const manifest = DatasetManifest.parse(
    JSON.parse(readFileSync(join(datasetDir, "manifest.json"), "utf8")),
  );
  const version = manifest.version;
  const rows = manifest.samples.map((entry) => {
    const file = JSON.parse(
      readFileSync(join(datasetDir, "samples", `${entry.sample_id}.json`), "utf8"),
    ) as Record<string, unknown>;
    return {
      ...entry,
      before: String(file["before"] ?? ""),
      after: String(file["after"] ?? ""),
      labels: labelsOf(file),
    } as DatasetSample;
  });
  // A mixed-language set is legitimate (ds-2 carries ts and js): one drill run
  // stages one language, and the rows it cannot stage are reported, not dropped
  // silently. The default is the language of the evaluated positives.
  const counts = new Map<string, number>();
  for (const row of rows) {
    if (row.split !== "eval" || row.labels.length === 0) continue;
    counts.set(row.language, (counts.get(row.language) ?? 0) + 1);
  }
  const language =
    requestedLanguage ??
    [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] ??
    rows[0]?.language ??
    "ts";
  const samples = rows.filter((row) => row.language === language);
  return { language, version, samples, skipped: rows.length - samples.length };
}

export function allSamples(plan: DrillPlan): PlannedSample[] {
  return [...plan.positives, ...plan.lowRisk, ...plan.controls, plan.probe];
}

export interface StageOptions {
  datasetDir: string;
  outDir: string;
  baseConfig: string;
  profile: string;
  plan: DrillPlan;
  /**
   * Gates the operator admitted were not green. Recorded, because a run that
   * degraded a gate is not the same run as one that did not.
   */
  degradedGates?: string[];
  /** The pin this run must be reproducible against, frozen before it started. */
  frozen: FrozenInstruments;
  /** What the probes saw; `null` fields mean "not probed", never "fine". */
  evidence: RunEvidence;
  /** The one-shot token: the run name, and any run it archived to get here. */
  oneShot: OneShot;
  /**
   * Build the graph and project every row's tier. On by default; tests stage a
   * tree without it, because the graph CLI is a measuring tool, not a fixture.
   * A run staged with `index: false` has `strata_projection: null`, which reads
   * as "not probed" and never as "projected and fine".
   */
  index?: boolean;
}

/** Where the frozen values live. A pin that is only in someone's head is not a pin. */
export { PREREGISTRATION, loadCostCeiling, loadFrozenBudgets, loadFrozenPin } from "./frozen.js";
import { loadCostCeiling, loadFrozenBudgets, loadFrozenPin, PREREGISTRATION } from "./frozen.js";

/** A run directory is self-identifying: eval-<dataset>-<timestamp>. */
export const RUN_DIR_PATTERN = /^(?:eval|smoke)-[A-Za-z0-9._-]+-\d{8}T\d{6}$/;

/** Every stage that reads or writes a run refuses an unnamed directory. */
export function assertRunDir(outDir: string): string {
  const name = outDir.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
  if (!RUN_DIR_PATTERN.test(name)) {
    throw new Error(
      `${outDir} is not a named run directory: the leaf must look like ` +
        `eval-${"<dataset version>"}-<yyyyMMddTHHmmss> (or smoke-...). ` +
        `An unnamed directory is how ds-1 residue ended up beside the ds-2 run.`,
    );
  }
  return name;
}

/** `runs/live/eval-ds-2.0.0-20261113T043000`. */
export function newRunDir(root: string, datasetVersion: string, kind: "eval" | "smoke", now = new Date()): string {
  const pad = (n: number): string => String(n).padStart(2, "0");
  const stamp =
    `${now.getFullYear()}${pad(now.getMonth() + 1)}${pad(now.getDate())}` +
    `T${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  const version = datasetVersion.length > 0 ? datasetVersion : "unknown";
  return join(root, `${kind}-${version}-${stamp}`);
}

export interface RunEvidence {
  /** How `plugin bundle` was judged, and what it saw. */
  bundle: {
    check: "mtime";
    bundle: string;
    bundle_mtime: string;
    newest_source: string;
    newest_source_mtime: string;
  } | null;
  /** `ocr llm test`: which model answered, and whether the tool loop works. */
  aor_probe: {
    ok: boolean;
    provider: string;
    served: string | null;
    url: string | null;
    configured: string | null;
    elapsed_ms: number;
  } | null;
  /** A scratch `ocr scan`: the token cost of one file, measured. */
  cost_probe: {
    tokens: number;
    elapsed_ms: number;
    file_lines: number;
    model: string | null;
    ran_at: string;
  } | null;
  /** What that probe implies for this plan, against the declared ceiling. */
  cost_estimate: {
    tokens: number;
    ceiling_tokens: number;
    rows: number;
    probe_tokens: number;
    method: string;
  } | null;
  /**
   * The tier each staged row will get, decided from the staged tree before the
   * run. No detector output is involved: only `impact` is queried.
   */
  strata_projection: {
    rows: StrataRow[];
    index_build_ms: Record<string, number>;
    asserted: string;
  } | null;
  /** How long the run should take, from the caps and the measured AOR probe. */
  wall_clock_estimate: {
    rows: number;
    per_row_ms: number;
    total_ms: number;
    index_build_ms: number;
    components: { semgrep_ms: number; crg_ms: number; aor_ms: number; basis: string };
  } | null;
}

export interface OneShot {
  run: string;
  at: string;
  /** Runs with the same dataset version that were archived to make room. */
  restarts: Array<{ archived: string; reason: string }>;
}

/**
 * One observation of the binary that produces the AOR numbers.
 *
 * The version line carries the commit; the hash catches a rebuilt binary that
 * reports the same commit, and the path says which installation was read.
 */
export interface OcrIdentity {
  version: string;
  binary: string | null;
  sha256: string | null;
  at: string;
}

/**
 * The same observation taken before and after the run.
 *
 * `ocr` updates itself from a detached child, so the binary can move *while*
 * the eval is running: a version check before the run cannot see it, and one
 * after the run cannot say when it happened. Two observations bracket the
 * window, and a difference is reported as `instrument_drifted` rather than as
 * a footnote.
 */
export interface OcrIdentityRecord {
  before: OcrIdentity | null;
  after: OcrIdentity | null;
  drifted: boolean;
}

export interface RunManifest {
  dataset_version: string;
  dataset_dir: string;
  config_hash: string;
  /** The pin the numbers must be reproduced against, frozen before the run. */
  frozen_instruments: FrozenInstruments;
  created_at: string;
  plan: { positives: number; low_risk: number; controls: number; probe: number; negatives_create: number };
  degraded_gates: string[];
  /** A proxy, and the manifest says so: the bundle is compared by mtime. */
  bundle_check: "mtime" | null;
  evidence: RunEvidence;
  /** The AOR binary before and after the run; a difference is not quotable. */
  ocr_identity: OcrIdentityRecord;
  cost: {
    estimate_tokens: number | null;
    ceiling_tokens: number | null;
    rows: number;
    method: string;
    actual: { tokens: number; rows: number; rows_without_tokens: number; wall_ms: number } | null;
  };
  one_shot: OneShot;
}

/**
 * What a fresh bundle looks like. `mtime` is a proxy: a checkout or a `touch`
 * moves it without changing the artefact, so it can be wrong in both
 * directions (usually red, which fails safe). It is recorded as `mtime` in
 * `run.json` so a later reader knows the judgement was a proxy; the upgrade is
 * a content hash injected at build time, tracked separately.
 */
async function bundleEvidence(): Promise<RunEvidence["bundle"]> {
  const bundle = resolve("dist/plugin.js");
  if (!existsSync(bundle)) return null;
  const newest = await newestSource("src");
  if (newest === null) return null;
  return {
    check: "mtime",
    bundle,
    bundle_mtime: new Date((await stat(bundle)).mtimeMs).toISOString(),
    newest_source: newest.path,
    newest_source_mtime: new Date(newest.at).toISOString(),
  };
}

/** First line of a command's output, or "" when it could not run. */
async function firstLineOf(command: string, args: string[]): Promise<string> {
  const result = await execa(command, args, { reject: false, timeout: 60_000 });
  return `${result.stdout ?? ""}${result.stderr ?? ""}`.trim().split("\n")[0]?.trim() ?? "";
}

/**
 * The installed `@alibaba-group/open-code-review` package.
 *
 * Read from the `ocr` shim on PATH, which is the binary that actually runs,
 * rather than from a path typed here: a second global install would otherwise
 * make the check describe a package nobody invokes.
 */
export async function ocrPackageDir(): Promise<string | null> {
  const locate = process.platform === "win32" ? "where" : "which";
  const shim = await firstLineOf(locate, ["ocr"]);
  const prefix = dirname(process.execPath);
  const candidates: string[] = [];
  if (shim.length > 0) {
    candidates.push(join(dirname(shim), "node_modules", "@alibaba-group", "open-code-review"));
  }
  candidates.push(join(prefix, "node_modules", "@alibaba-group", "open-code-review"));
  candidates.push(join(prefix, "..", "lib", "node_modules", "@alibaba-group", "open-code-review"));
  return candidates.find((candidate) => existsSync(join(candidate, "package.json"))) ?? null;
}

/** The native binary inside the installed package, whatever its platform dir. */
async function findNativeBinary(root: string, depth = 0): Promise<string | null> {
  if (depth > 6) return null;
  let entries;
  try {
    entries = await readdir(root, { withFileTypes: true });
  } catch {
    return null;
  }
  for (const entry of entries) {
    if (entry.isFile() && /^opencodereview(\.exe)?$/.test(entry.name)) return join(root, entry.name);
  }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name === ".git") continue;
    const found = await findNativeBinary(join(root, entry.name), depth + 1);
    if (found !== null) return found;
  }
  return null;
}

/**
 * What `ocr` is, right now.
 *
 * `ocr --version` names the build; the hash names the file. Both are recorded
 * because a rebuild can keep the commit string, and a missing hash says the
 * check could not be made rather than that the binary matched.
 */
export async function ocrIdentity(): Promise<OcrIdentity> {
  const version = await firstLineOf("ocr", ["--version"]);
  const pkg = await ocrPackageDir();
  const binary = pkg === null ? null : await findNativeBinary(pkg);
  const sha256 =
    binary === null ? null : createHash("sha256").update(await readFile(binary)).digest("hex");
  return { version, binary, sha256, at: new Date().toISOString() };
}

/** Did the AOR binary move between the two observations? */
export function ocrDrifted(before: OcrIdentity, after: OcrIdentity): boolean {
  if (before.sha256 !== null && after.sha256 !== null) return before.sha256 !== after.sha256;
  return before.version !== after.version;
}

/**
 * Where the self-updater lives, and whether it is still there.
 *
 * `OCR_NO_UPDATE=1` is a declaration that can be unset — and the update that
 * replaced the binary on 2026-11-13 arrived through a detached child that had
 * been spawned *before* the pin was restored, so no environment variable at
 * that moment could have stopped it. Renaming the file is a fact: the launcher
 * has nothing to spawn.
 */
export async function ocrUpdaterFile(): Promise<{ path: string; present: boolean } | null> {
  const pkg = await ocrPackageDir();
  if (pkg === null) return null;
  const path = join(pkg, "scripts", "update.js");
  return { path, present: existsSync(path) };
}

/** Take one observation and write it into `run.json`, keeping the other side. */
export async function recordOcrIdentity(
  outDir: string,
  phase: "before" | "after",
): Promise<OcrIdentityRecord> {
  const manifestPath = join(outDir, "run.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as RunManifest;
  const record: OcrIdentityRecord = manifest.ocr_identity ?? {
    before: null,
    after: null,
    drifted: false,
  };
  record[phase] = await ocrIdentity();
  record.drifted =
    record.before !== null && record.after !== null
      ? ocrDrifted(record.before, record.after)
      : false;
  manifest.ocr_identity = record;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return record;
}

async function writeRunManifest(options: StageOptions): Promise<RunManifest> {  const manifest: RunManifest = {
    dataset_version: options.plan.datasetVersion,
    dataset_dir: resolve(options.datasetDir),
    config_hash: sha256(await readFile(options.baseConfig, "utf8")),
    frozen_instruments: options.frozen,
    created_at: new Date().toISOString(),
    plan: {
      positives: options.plan.positives.length,
      low_risk: options.plan.lowRisk.length,
      controls: options.plan.controls.length,
      probe: 1,
      // Counted over the staged dataset rows, not over `lowRisk`: the create
      // sample is too large to be low risk now (it needs to be a real write),
      // and it is still staged as a behaviour sample. The dep probe is not a
      // dataset row and is not counted here.
      negatives_create: [...options.plan.positives, ...options.plan.lowRisk, ...options.plan.controls].filter(
        (sample) => sample.eventKind === "create",
      ).length,
    },
    degraded_gates: [...(options.degradedGates ?? [])],
    bundle_check: options.evidence.bundle?.check ?? null,
    evidence: options.evidence,
    // Filled by the run stage: staging is not running, and an identity taken
    // before any row exists would describe the wrong window.
    ocr_identity: { before: null, after: null, drifted: false },
    cost: {
      estimate_tokens: options.evidence.cost_estimate?.tokens ?? null,
      ceiling_tokens: options.evidence.cost_estimate?.ceiling_tokens ?? null,
      rows: options.evidence.cost_estimate?.rows ?? 2 * allSamples(options.plan).length,
      method:
        options.evidence.cost_estimate?.method ??
        "probe tokens x 2 (preview + scan) x staged rows x 1.5 (correction headroom); " +
          "an upper bound on AOR spend, not a prediction of the driver's tokens",
      actual: null,
    },
    one_shot: options.oneShot,
  };
  await writeFile(join(options.outDir, "run.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  return manifest;
}

/**
 * Refuse a directory that was staged on another dataset. Dataset identity is
 * the same class of fact as instrument identity: a consumer that cannot check
 * it will eventually mix two measurements.
 */
export function readRunManifest(outDir: string, datasetDir: string): RunManifest {
  assertRunDir(outDir);
  const path = join(outDir, "run.json");
  if (!existsSync(path)) {
    throw new Error(`${outDir} has no run.json: stage the run before collecting or evaluating it`);
  }
  const manifest = JSON.parse(readFileSync(path, "utf8")) as RunManifest;
  const actual = JSON.parse(readFileSync(join(datasetDir, "manifest.json"), "utf8")) as { version?: string };
  if (manifest.dataset_version !== actual.version) {
    throw new Error(
      `${outDir} was staged on dataset ${manifest.dataset_version}, ` +
        `but ${datasetDir} is ${String(actual.version)}: refusing to mix measurements`,
    );
  }
  return manifest;
}

/** Materialise the scratch repos, configs and profile overlays for one run. */
/**
 * Three clean importers per positive row.
 *
 * `staticTier` reads one thing: how many files the change event carries. The
 * host's write tool carries exactly one `file_path`, so a one-file change is
 * tier 0 however large the file is, and no amount of vulnerable code in it moves
 * the tier. The graph reads something else: a file with three dependants has a
 * blast radius of four files, which is tier 1 under the *same*
 * `tier0.filesMax` boundary.
 *
 * These files therefore do not change the review unit - the change event is
 * still one file, and AOR still scans one file - they change what the repository
 * says about that file, which is the question the triage layer exists to answer.
 * Each is a single import statement: it carries the edge the graph needs, and it
 * has no code in it that a detector could find.
 */
export const IMPORTERS_PER_POSITIVE = 3;

export function importerPath(sample: PlannedSample, index: number): string {
  return `live/${sample.sampleId}/__importers__/${index}.ts`;
}

/** The specifier is the edge; the graph resolves `../<name>.ts` as written. */
export function importerText(target: string): string {
  return `import "../${basename(target)}";\n`;
}

/** One row of the projection: what the triage layer would decide, before the run. */
export interface StrataRow {
  sample_id: string;
  stratum: "A" | "B";
  path: string;
  tier: Tier;
  tier_source: "triage" | "static" | "none";
  impacted_files: number;
  impacted_nodes: number;
  skip_reason: string | null;
  ms: number;
}

/**
 * Index the staged tree.
 *
 * The plugin only ever queries the graph; it never builds one, and a query
 * against a missing index takes the degraded path. So the index is built here,
 * once per baseline, after the baseline commit and before the run - and the
 * time it takes is recorded, because it is part of the run's wall clock.
 */
export async function buildIndex(root: string): Promise<number> {
  const started = Date.now();
  await execa("code-review-graph", ["build", "--repo", root, "-q", "--skip-flows"], {
    cwd: root,
    timeout: 600_000,
  });
  return Date.now() - started;
}

/**
 * Ask the real triage layer, on the real staged tree, what each row's tier is.
 *
 * Zero detector output is produced here: only `impact` runs, so the projection
 * costs no blindness. It exists because three clean importers per positive row
 * turn tier 0 into tier 1 by blast radius, and a negative row on a file that
 * happens to have three importers of its own would silently become tier 1 too -
 * at which point line 4 ("no false positive on the low-risk pool") would stop
 * measuring tier 0 while the report still printed `pairs=8`.
 */
export async function projectStrata(
  root: string,
  config: RunConfig,
  samples: PlannedSample[],
  datasetDir: string,
): Promise<StrataRow[]> {
  const triage = createCrgTriage(config, { root });
  const boundaries = { tier0: config.triage.tier0, tier1: config.triage.tier1 };
  const rows: StrataRow[] = [];
  for (const sample of samples) {
    if (sample.kind === "dep-probe") continue;
    const after = stagedText(sample, datasetDir);
    const event: ChangeEvent = {
      id: `strata-${sample.sampleId}`,
      sessionId: "strata",
      rootCallId: "strata",
      phase: "post",
      trigger: "write",
      files: [sample.path],
      diff: synthesizeDiff(sample.path, "", after),
      diffProvenance: "synthesized",
      ts: Date.now(),
    };
    const started = Date.now();
    const analysis = await triage.analyze(event, Date.now() + config.budgets.crgQueryMs);
    const ms = Date.now() - started;
    const decision = computeTier(
      {
        changedFiles: 1,
        impactedFiles: analysis.impactedFiles,
        impactedNodes: analysis.impactedNodes,
        truncated: analysis.truncated,
        unresolvedCallSites: analysis.unresolvedCallSites,
        indexReady: analysis.indexReady,
        indexStale: analysis.indexStale,
      },
      boundaries,
    );
    rows.push({
      sample_id: sample.sampleId,
      stratum: sample.kind === "positive" ? "B" : "A",
      path: sample.path,
      tier: decision.tier,
      tier_source: decision.source,
      impacted_files: analysis.impactedFiles,
      impacted_nodes: analysis.impactedNodes,
      skip_reason: decision.skipReason,
      ms,
    });
  }
  return rows;
}

/**
 * The projection is a precondition, not a report.
 *
 * Line 4 measures false positives on a pool of defect-free changes that are
 * supposed to stay below the tier boundary; line 3 and line 5 need AOR to have
 * run at all, which happens only above it. A row that lands in the wrong stratum
 * makes one of those lines vacuous while still printing a number, so the run
 * refuses to start instead of averaging it away afterwards.
 */
export function assertStrata(rows: StrataRow[]): void {
  const negatives = rows.filter((row) => row.stratum === "A");
  const positives = rows.filter((row) => row.stratum === "B");
  const problems: string[] = [];
  for (const row of negatives) {
    if (row.tier !== 0) {
      problems.push(`negative ${row.sample_id} is tier ${row.tier} (want 0): ${row.impacted_files} files`);
    }
  }
  for (const row of positives) {
    if (row.tier < 1 || row.tier_source !== "triage") {
      problems.push(
        `positive ${row.sample_id} is tier ${row.tier} source ${row.tier_source} (want >= 1 by triage): ` +
          `${row.impacted_files} files, skip ${row.skip_reason ?? "none"}`,
      );
    }
  }
  if (problems.length > 0) {
    throw new Error(
      `stratification projection failed, refusing to stage the run:\n  ${problems.join("\n  ")}\n` +
        `A negative that is tier >= 1 removes line 4's denominator; a positive that is tier 0 removes ` +
        `AOR from the row entirely. Fix the staged tree (importers, or which file a row writes) - do ` +
        `not let the report average this out.`,
    );
  }
}

export function formatStrata(rows: StrataRow[], buildMs: Record<string, number>): string {
  const lines = rows.map(
    (row) =>
      `  ${row.stratum} ${row.sample_id} tier=${row.tier} via ${row.tier_source} ` +
      `files=${row.impacted_files} nodes=${row.impacted_nodes} ${row.ms}ms`,
  );
  const counts = rows.reduce<Record<string, number>>((acc, row) => {
    const key = `${row.stratum}:tier${row.tier}`;
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  const index = Object.entries(buildMs)
    .map(([baseline, ms]) => `${baseline} ${ms}ms`)
    .join(", ");
  return (
    `strata projection (no detector was run): ${JSON.stringify(counts)}\n` +
    `${lines.join("\n")}\n` +
    `index build: ${index}`
  );
}

/**
 * B4 and B4g are two configs, not one config under two labels.
 *
 * The only difference between them is `triage.enabled`, which is the whole point
 * of line 4's pairing: B4 runs the tier decision, B4g does not. Staging both
 * baselines from `b4.json` would have run the same ladder twice and printed the
 * difference as an effect of triage.
 */
export function baselineConfigPath(baseConfig: string, baseline: "B4" | "B4g"): string {
  if (baseline === "B4") return baseConfig;
  const sibling = baseConfig.replace(/b4\.json$/, "b4g.json");
  if (sibling === baseConfig) {
    throw new Error(
      `cannot derive the B4g config from ${baseConfig}: B4g differs from B4 in triage.enabled, ` +
        `so staging both from one file would run the same ladder twice`,
    );
  }
  if (!existsSync(sibling)) throw new Error(`missing ${sibling}: the B4g baseline needs its own config`);
  return sibling;
}

export async function stageDrill(options: StageOptions): Promise<void> {
  assertRunDir(options.outDir);
  const samples = allSamples(options.plan);
  const strataRows: StrataRow[] = [];
  const indexBuildMs: Record<string, number> = {};

  for (const baseline of ["B4", "B4g"] as const) {
    const basePath = baselineConfigPath(options.baseConfig, baseline);
    const base = JSON.parse(await readFile(basePath, "utf8")) as Record<string, unknown>;
    const scratch = join(options.outDir, "scratch", baseline);
    await mkdir(scratch, { recursive: true });
    await writeFile(join(scratch, "README.md"), `# CRS live drill ${baseline}\n`, "utf8");
    await mkdir(join(scratch, ".staging"), { recursive: true });
    for (const sample of samples) {
      await writeFile(join(scratch, sample.staged), stagedText(sample, options.datasetDir), "utf8");
      const target = join(scratch, sample.path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, "", "utf8");
    }
    // Positives get three importers each: the run's change event stays one file,
    // but the repository now has a blast radius for that file, which is what
    // `computeTier` reads. Negatives get none, so they stay at tier 0.
    for (const sample of samples) {
      if (sample.kind !== "positive") continue;
      for (let index = 1; index <= IMPORTERS_PER_POSITIVE; index += 1) {
        const path = importerPath(sample, index);
        const target = join(scratch, path);
        await mkdir(dirname(target), { recursive: true });
        await writeFile(target, importerText(sample.path), "utf8");
      }
    }
    await writeFile(
      join(scratch, "plan.json"),
      `${JSON.stringify(
        samples.map((sample) => ({ path: sample.path, staged: sample.staged })),
        null,
        2,
      )}\n`,
      "utf8",
    );
    await git(scratch, ["init", "-q"]);
    await git(scratch, ["config", "user.email", "crs-drill@example.com"]);
    await git(scratch, ["config", "user.name", "CRS drill"]);

    // Ruleset paths in the config are repo-relative; the adapter resolves them
    // against its root, so the scratch repo needs the same tree.
    const subsets = ((base["sources"] as Record<string, unknown>)["semgrep"] as {
      subsets?: Array<{ path: string }>;
    }).subsets ?? [];
    for (const subset of subsets) {
      const source = resolve(subset.path);
      if (!existsSync(source)) throw new Error(`ruleset not found: ${source}`);
      const destination = join(scratch, subset.path);
      await mkdir(dirname(destination), { recursive: true });
      await copyFile(source, destination);
    }

    await git(scratch, ["add", "-A"]);
    await git(scratch, ["commit", "-q", "-m", "drill baseline"]);

    const config = {
      ...base,
      mode: "live" as Mode,
      baseline: baseline as Baseline,
      sources: {
        ...(base["sources"] as Record<string, unknown>),
        registry: {
          ...((base["sources"] as Record<string, Record<string, unknown>>)["registry"] ?? {}),
          enabled: true,
        },
      },
      persistence: {
        ...(base["persistence"] as Record<string, unknown>),
        jsonlPath: join(options.outDir, baseline, "review.jsonl"),
      },
    } as unknown as RunConfig;
    // The staged config is the one the plugin will load, so it is the one the
    // budget relation has to hold for. Failing here costs a staging run; failing
    // at load costs the run.
    assertBudgetRelations(config);

    if (options.index !== false) {
      const buildMs = await buildIndex(scratch);
      const rows = await projectStrata(scratch, config, samples, options.datasetDir);
      assertStrata(rows);
      process.stdout.write(`${baseline}: ${formatStrata(rows, { [baseline]: buildMs })}\n`);
      strataRows.push(...rows);
      indexBuildMs[baseline] = buildMs;
    }
    const configPath = join(options.outDir, baseline, "config.json");
    await mkdir(dirname(configPath), { recursive: true });
    await writeFile(configPath, `${JSON.stringify(config, null, 2)}\n`, "utf8");

    const overlayPath = join(options.outDir, baseline, "overlay.yml");
    await writeFile(
      overlayPath,
      [
        "- id: code-review-system",
        "  config:",
        `    configPath: ${toYamlPath(configPath)}`,
        `    root: ${toYamlPath(scratch)}`,
        `    artifactPath: ${toYamlPath(resolve("artifacts/calibration.json"))}`,
        "",
      ].join("\n"),
      "utf8",
    );
  }
  options.evidence.strata_projection = {
    rows: strataRows,
    index_build_ms: indexBuildMs,
    asserted: "A: tier 0; B: tier >= 1 by triage (index_not_ready would fail the run)",
  };
  const estimate = options.evidence.wall_clock_estimate;
  if (estimate) {
    estimate.index_build_ms = Object.values(indexBuildMs).reduce((sum, ms) => sum + ms, 0);
    estimate.total_ms += estimate.index_build_ms;
  }
  await writeRunManifest(options);
}

function stagedText(sample: PlannedSample, datasetDir: string): string {
  if (sample.kind === "dep-probe") return DEP_PROBE_BODY;
  const raw = JSON.parse(
    readFileSync(join(datasetDir, "samples", `${sample.sampleId}.json`), "utf8"),
  ) as { after: string };
  return raw.after;
}

function toYamlPath(path: string): string {
  return path.replace(/\\/g, "/");
}

async function git(cwd: string, args: string[]): Promise<void> {
  await execa("git", args, { cwd, reject: true });
}

export function writePrompt(count: number): string {
  return [
    "You are the driver for a live acceptance drill. Work only inside the current directory.",
    "Read plan.json: it is a JSON array of { path, staged }.",
    "For every entry, call the write tool exactly once:",
    "  file_path = <path>, content = the exact text of <staged>.",
    "Copy the staged text verbatim; do not reformat, do not summarise, do not use bash, do not skip entries.",
    `There are ${count} entries. When every write is done, reply with exactly: DONE <count>.`,
  ].join("\n");
}

export const CORRECTION_PROMPT = [
  "You previously received one or more [CRS-WARN] review messages in this session.",
  "For every [CRS-WARN] you received, open the file it names and fix the flagged issue with the edit tool,",
  "keeping the file's behaviour intact (same exports and semantics).",
  "Do not reformat unrelated code and do not touch files that were not named.",
  "When done, reply with exactly: FIXED <count>.",
].join("\n");

export interface RunOptions {
  outDir: string;
  profile: string;
  baseline: "B4" | "B4g";
  timeoutMs?: number;
  correction?: boolean;
  sessionId?: string;
}

/** One headless DSH invocation against the staged baseline repo. */
function toolPath(): string {
  const local = join(homedir(), ".local", "bin");
  const current = process.env["PATH"] ?? "";
  return current.includes(local) ? current : `${local}${process.platform === "win32" ? ";" : ":"}${current}`;
}

/**
 * `dsh` on PATH is a PowerShell shim. Launching it from here would route the
 * whole session through that shim's process wrapper, which on Windows has no
 * access to the certificate store; semgrep-core then dies in its CA bootstrap
 * (`CertOpenSystemStore returned NULL`) before any rule runs. Invoking the JS
 * entry with this node binary keeps the token that semgrep needs.
 */
export function dshBinPath(): string {
  const override = process.env["DSH_BIN"];
  if (override !== undefined && override.length > 0) return override;
  return join(dirname(process.execPath), "node_modules", "@deepseek-ai", "dsh", "lib", "bin.js");
}

export interface Preflight {
  ok: boolean;
  checks: Array<{ name: string; ok: boolean; detail: string }>;
  /** What the probes saw, carried into `run.json` so the numbers have evidence. */
  evidence: RunEvidence;
}

export interface PreflightOptions {
  plan?: DrillPlan;
  /** Ruleset the baseline config actually loads for TypeScript. */
  ruleset?: string;
  datasetDir?: string;
  /** Commit the AOR numbers must come from; empty means the pin is not asserted. */
  aorCommit?: string;
  /** The config whose declared pin is compared with the frozen one. */
  baseConfig?: string;
  /** The frozen pin; when given, config and probe are both compared with it. */
  frozen?: FrozenInstruments;
}

/**
 * The TS ruleset is whatever the baseline config declares, not a file name
 * typed here twice. `ts_all.yaml` and the config's `ts_dedup.yaml` differ, and
 * a hardcoded path silently measures a different ruleset than the one under
 * test.
 */
export function pinnedTsRuleset(baseConfig: string): string {
  const base = JSON.parse(readFileSync(baseConfig, "utf8")) as {
    sources?: { semgrep?: { subsets?: Array<{ path: string; langs?: string[] }> } };
  };
  const subset = (base.sources?.semgrep?.subsets ?? []).find((candidate) =>
    (candidate.langs ?? []).some((lang) => semgrepLanguage(lang) === "typescript"),
  );
  if (subset === undefined) throw new Error(`no typescript ruleset subset declared in ${baseConfig}`);
  return subset.path;
}

/** The AOR commit the config claims the budgets were verified on (#22). */
export function pinnedAorCommit(baseConfig: string): string {
  const base = JSON.parse(readFileSync(baseConfig, "utf8")) as {
    sources?: { aor?: { versionCommit?: string } };
  };
  return base.sources?.aor?.versionCommit ?? "";
}

/**
 * Fail fast, and for the right reason. Semgrep in particular can be installed
 * yet crash before rule matching (`CertOpenSystemStore returned NULL` in its
 * OCaml CA bootstrap), which otherwise only surfaces as a degraded scan.
 */
/** Newest mtime under `dir`; null when the tree is empty. */
async function newestSource(dir: string): Promise<{ path: string; at: number } | null> {
  let newest: { path: string; at: number } | null = null;
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    if (!/\.(ts|tsx|json)$/.test(entry.name)) continue;
    const path = join(entry.parentPath ?? dir, entry.name);
    const at = (await stat(path)).mtimeMs;
    if (newest === null || at > newest.at) newest = { path, at };
  }
  return newest;
}

/** The pin as the config declares it. Only ever compared with the frozen pin. */
function frozenFromConfig(baseConfig: string): {
  semgrep: { version: string };
  ocr: { commit: string };
  budgets: { crgQueryMs: number; semgrepKillMs: number; callMs: number };
} {
  const base = JSON.parse(readFileSync(baseConfig, "utf8")) as {
    sources?: { semgrep?: { version?: string }; aor?: { versionCommit?: string } };
    budgets?: { crgQueryMs?: number; semgrepKillMs?: number; callMs?: number };
  };
  return {
    semgrep: { version: base.sources?.semgrep?.version ?? "" },
    ocr: { commit: base.sources?.aor?.versionCommit ?? "" },
    budgets: {
      crgQueryMs: base.budgets?.crgQueryMs ?? 0,
      semgrepKillMs: base.budgets?.semgrepKillMs ?? 0,
      callMs: base.budgets?.callMs ?? 0,
    },
  };
}

function sameCommitText(a: string, b: string): boolean {
  return a.length > 0 && b.length > 0 && (a.startsWith(b) || b.startsWith(a));
}

async function trackedFiles(): Promise<string[]> {
  const listed = await execa("git", ["ls-files", "-z"], { reject: true });
  return `${listed.stdout ?? ""}`.split("\0").filter((file) => file.length > 0);
}

async function trackedFileCount(): Promise<number> {
  return (await trackedFiles()).length;
}

/**
 * Files under version control whose bytes contain `needle`.
 *
 * `git grep` would put the secret on a command line, where every process on the
 * machine can read it; this reads the working tree instead. Binary files are
 * safe to search this way because the comparison is on raw bytes.
 */
async function trackedFilesContaining(needle: string): Promise<string[]> {
  if (needle.length < 8) {
    throw new Error("the key is shorter than 8 characters, which is not a usable credential");
  }
  const hits: string[] = [];
  for (const file of await trackedFiles()) {
    let bytes: Buffer;
    try {
      bytes = await readFile(file);
    } catch {
      continue;
    }
    if (bytes.length > 8_000_000) continue;
    if (bytes.includes(needle, 0, "utf8")) hits.push(file);
  }
  return hits;
}

export async function preflight(profile: string, options: PreflightOptions = {}): Promise<Preflight> {
  const checks: Preflight["checks"] = [];
  const evidence: RunEvidence = {
    bundle: null,
    aor_probe: null,
    cost_probe: null,
    cost_estimate: null,
    strata_projection: null,
    wall_clock_estimate: null,
  };
  const env = { ...process.env, PATH: toolPath(), ...TOOL_ENV };

  const run = async (name: string, file: string, args: string[], cwd = process.cwd()) => {
    const result = await execa(file, args, { cwd, env, reject: false, timeout: 120_000 });
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    checks.push({
      name,
      ok: result.exitCode === 0,
      // One line only: `semgrep scan --json` prints its whole envelope on one
      // line, which otherwise buries the rest of the table.
      detail: result.exitCode === 0 ? (output.split("\n")[0] ?? "").slice(0, 160) : output.slice(-400),
    });
    return result.exitCode === 0;
  };

  await run("semgrep version", "semgrep", ["--version"]);
  const probeDir = join(tmpdir(), `crs-semgrep-probe-${Date.now()}`);
  await mkdir(probeDir, { recursive: true });
  const probeFile = join(probeDir, "probe.ts");
  await writeFile(probeFile, "const x = 1;\n", "utf8");
  const semgrepScans = await run(
    "semgrep scan",
    "semgrep",
    [
      "--config",
      resolve("research/semgrep-bench/snapshot/ts_dedup.yaml"),
      "--json",
      "--metrics",
      "off",
      "--disable-version-check",
      probeFile,
    ],
    probeDir,
  );
  await run("ocr", "ocr", ["--version"]);
  if (options.aorCommit !== undefined && options.aorCommit.length > 0) {
    const probe = await execa("ocr", ["--version"], { env, reject: false, timeout: 120_000 });
    const text = `${probe.stdout ?? ""}${probe.stderr ?? ""}`.trim().split("\n")[0] ?? "";
    // `ocr` self-updates. The budgets in #22 were measured on one commit, so a
    // drifted binary makes every AOR number unquotable until it is re-pinned.
    const matches = probe.exitCode === 0 && text.includes(options.aorCommit);
    const identity = await ocrIdentity();
    const stamp =
      identity.sha256 === null ? "sha256 unresolved" : `sha256 ${identity.sha256.slice(0, 12)}`;
    checks.push({
      name: "ocr pin",
      ok: matches,
      detail: matches
        ? `${text} ${stamp}`
        : `${text} ${stamp} - config pins ${options.aorCommit}; re-pin before quoting AOR numbers`,
    });
  }
  // The pin above is an observation; this is the mechanism behind it. The
  // environment variable was set at user scope and the binary still moved,
  // because the updater had already been spawned detached. A file that is not
  // there cannot be spawned, unset, or raced.
  try {
    const updater = await ocrUpdaterFile();
    if (updater === null) {
      checks.push({
        name: "ocr updater",
        ok: false,
        detail: "could not locate the installed open-code-review package",
      });
    } else {
      checks.push({
        name: "ocr updater",
        ok: !updater.present,
        detail: updater.present
          ? `${updater.path} still exists: the launcher can spawn it at any moment; ` +
            "rename it before the eval window"
          : `${updater.path} is absent: the launcher has nothing to spawn`,
      });
    }
  } catch (error) {
    checks.push({
      name: "ocr updater",
      ok: false,
      detail: (error as Error).message.slice(-300),
    });
  }
  await run("code-review-graph", "code-review-graph", ["--help"]);
  // #7 D2: the calibration artifact must have been fitted on *this* dataset and
  // ruleset. A stale artifact silently applies a per-class threshold that was
  // fitted on another class set (the old one still carried CWE-502).
  try {
    const artifact = await loadCalibration(resolve("artifacts/calibration.json"));
    const rulesTablePath = resolve(RULES_TABLE);
    const rulesetFingerprint = sha256(await readFile(rulesTablePath, "utf8"));
    const manifestRaw = JSON.parse(
      await readFile(resolve("datasets/self-built/manifest.json"), "utf8"),
    ) as { version?: unknown; samples?: Array<{ cwe?: unknown }> };
    const categories = calibrationCategories(
      (manifestRaw.samples ?? []).map((sample) =>
        typeof sample.cwe === "string" ? sample.cwe : null,
      ),
      [...declaredCoverage(loadRulesTable(rulesTablePath), "typescript").perCwe.keys()],
    );
    assertCalibrationMatches(artifact, {
      datasetVersion: typeof manifestRaw.version === "string" ? manifestRaw.version : undefined,
      rulesetFingerprint,
      categories,
    });
    checks.push({
      name: "calibration artifact",
      ok: true,
      detail: `categories ${categories.join(" ")}`,
    });
  } catch (error) {
    checks.push({
      name: "calibration artifact",
      ok: false,
      detail: (error as Error).message.slice(-400),
    });
  }
  // The rows come from `dist/plugin.js`, not from `src/`. A bundle older than the
  // tree passes every other gate and then writes rows in the old shape, which the
  // evaluator refuses - after the one eval has been spent. This is the same
  // "declared != shipped" family as `ts_all` vs `ts_dedup`, so it is a gate.
  //
  // The comparison is mtime, which is a proxy: a checkout or a copy moves it
  // without touching the artefact, and source edited back to its old text still
  // looks new. It fails red more often than green, so it is kept for now, but
  // the manifest records `bundle_check: "mtime"` and the check prints both
  // timestamps, so a false red is diagnosable in one line.
  try {
    const bundle = await bundleEvidence();
    if (bundle === null) {
      throw new Error(
        !existsSync(resolve("dist/plugin.js"))
          ? "dist/plugin.js is missing: run `npm run build`"
          : "no sources under src/ to compare against",
      );
    }
    evidence.bundle = bundle;
    if (Date.parse(bundle.newest_source_mtime) > Date.parse(bundle.bundle_mtime)) {
      throw new Error(
        `${bundle.newest_source} (${bundle.newest_source_mtime}) is newer than ` +
          `${bundle.bundle} (${bundle.bundle_mtime}): run \`npm run build\``,
      );
    }
    checks.push({
      name: "plugin bundle",
      ok: true,
      detail:
        `${bundle.bundle} mtime=${bundle.bundle_mtime} >= newest src ` +
        `${bundle.newest_source} mtime=${bundle.newest_source_mtime} (proxy: mtime)`,
    });
  } catch (error) {
    checks.push({
      name: "plugin bundle",
      ok: false,
      detail: (error as Error).message.slice(-400),
    });
  }
  // `ocr`'s commit says which client asked; this says which model answered.
  // The probe is a real request, not a config read: an expired key or an empty
  // quota passes every local check and then degrades every AOR row, which is
  // the one thing P2/P4 cannot survive.
  const probeStarted = Date.now();
  const aorProbe = await execa("ocr", ["llm", "test"], { env, reject: false, timeout: 120_000 });
  const aorText = `${aorProbe.stdout ?? ""}\n${aorProbe.stderr ?? ""}`.trim();
  const parsedAor = parseAorProbe(aorText);
  const aorElapsed = Date.now() - probeStarted;
  const aorOk =
    aorProbe.exitCode === 0 && parsedAor.served !== null && parsedAor.roundTrip;
  evidence.aor_probe = {
    ok: aorOk,
    provider: parsedAor.provider,
    served: parsedAor.served,
    url: parsedAor.url,
    configured: configuredModelOf(parsedAor.provider),
    elapsed_ms: aorElapsed,
  };
  checks.push({
    name: "aor model",
    ok: aorOk,
    detail: aorOk
      ? `${parsedAor.provider} served ${parsedAor.served} ` +
        `(requested ${evidence.aor_probe.configured ?? "unknown"}) at ${parsedAor.url ?? "?"} ` +
        `in ${aorElapsed}ms, tool round trip ok`
      : `probe failed in ${aorElapsed}ms: ${aorText.split("\n").slice(-3).join(" ").slice(-300)}`,
  });
  // The pin is a claim about *this* run; the config is the thing under test.
  // Comparing them means an edit to the config cannot silently move the pin.
  if (options.frozen !== undefined) {
    const configPin = frozenFromConfig(
      options.baseConfig ?? resolve(arg("--config", "configs/b4.json")),
    );
    const mismatches: string[] = [];
    if (configPin.semgrep.version !== options.frozen.semgrep.version) {
      mismatches.push(
        `config semgrep ${configPin.semgrep.version} != frozen ${options.frozen.semgrep.version}`,
      );
    }
    if (!sameCommitText(configPin.ocr.commit, options.frozen.ocr.commit)) {
      mismatches.push(`config ocr ${configPin.ocr.commit} != frozen ${options.frozen.ocr.commit}`);
    }
    if (aorOk && parsedAor.served !== options.frozen.aor_model.id) {
      mismatches.push(
        `served model ${parsedAor.served} != frozen ${options.frozen.aor_model.id} ` +
          `- the service is answering with a different ruler than the one this run is frozen against`,
      );
    }
    checks.push({
      name: "frozen pin",
      ok: mismatches.length === 0,
      detail:
        mismatches.length === 0
          ? `${PREREGISTRATION} agrees with the config and with the probes`
          : mismatches.join("; "),
    });

    // `crgQueryMs` decides whether the triage layer answers at all, so it is
    // pinned like an instrument rather than left as a tunable: a value below the
    // graph CLI's floor does not slow the tier down, it removes it.
    const frozenBudgets = loadFrozenBudgets();
    const configBudgets = frozenFromConfig(
      options.baseConfig ?? resolve(arg("--config", "configs/b4.json")),
    ).budgets;
    const prePath = configBudgets.semgrepKillMs + configBudgets.crgQueryMs;
    const fits = prePath <= configBudgets.callMs;
    const matches = frozenBudgets !== null && configBudgets.crgQueryMs === frozenBudgets.crg_query_ms;
    checks.push({
      name: "crg budget",
      ok: matches && fits,
      detail: !fits
        ? `semgrepKillMs ${configBudgets.semgrepKillMs} + crgQueryMs ${configBudgets.crgQueryMs} = ` +
          `${prePath}ms exceeds callMs ${configBudgets.callMs}ms`
        : frozenBudgets === null
          ? `${PREREGISTRATION} has no frozen.budgets.crg_query_ms: the value that decides whether ` +
            `the triage layer answers was never frozen, so there is nothing to hold the config to`
          : matches
            ? `crgQueryMs ${configBudgets.crgQueryMs} == frozen; pre path ${configBudgets.semgrepKillMs} + ` +
              `${configBudgets.crgQueryMs} = ${prePath}ms <= callMs ${configBudgets.callMs}ms` +
              `${frozenBudgets.derivation === null ? "" : `; ${frozenBudgets.derivation}`}`
            : `config crgQueryMs ${configBudgets.crgQueryMs} != frozen ${frozenBudgets.crg_query_ms}`,
    });
  }
  // The repository is public. A key that lands in a tracked file is a leak no
  // `.gitignore` can undo, so the check reads the key from the environment and
  // greps the *tracked* tree for its value. Paths are printed; the value is not.
  const secret = process.env["DEEPSEEK_API_KEY"] ?? "";
  if (secret.length > 0) {
    try {
      const leaks = await trackedFilesContaining(secret);
      checks.push({
        name: "secret not tracked",
        ok: leaks.length === 0,
        detail:
          leaks.length === 0
            ? `DEEPSEEK_API_KEY not found in ${await trackedFileCount()} tracked files`
            : `DEEPSEEK_API_KEY appears in ${leaks.length} tracked file(s): ${leaks.slice(0, 5).join(", ")}`,
      });
    } catch (error) {
      checks.push({
        name: "secret not tracked",
        ok: false,
        detail: `could not scan tracked files: ${(error as Error).message.slice(-300)}`,
      });
    }
  }
  const profileCheck = await execa(process.execPath, [dshBinPath(), "plugin", "--profile", profile, "list"], {
    env,
    reject: false,
    timeout: 120_000,
  });
  checks.push({
    name: "dsh profile",
    ok: profileCheck.exitCode === 0,
    detail: profileCheck.exitCode === 0 ? `profile ${profile} reachable` : `${profileCheck.stderr}`.slice(-300),
  });
  checks.push({
    name: "DEEPSEEK_API_KEY",
    ok: typeof process.env["DEEPSEEK_API_KEY"] === "string" && process.env["DEEPSEEK_API_KEY"].length > 0,
    detail: process.env["DEEPSEEK_API_KEY"] ? "present" : "missing",
  });

  if (!semgrepScans) {
    checks.push({
      name: "semgrep blocking path",
      ok: false,
      detail:
        "semgrep cannot scan here; line1 has no mechanical-block evidence until this is fixed (see the crash above)",
    });
  }
  return { ok: checks.every((check) => check.ok), checks, evidence };
}

export async function runTask(options: RunOptions, prompt: string): Promise<{ stdout: string; sessionId: string | null }> {
  const scratch = join(options.outDir, "scratch", options.baseline);
  const overlay = join(options.outDir, options.baseline, "overlay.yml");
  const args = ["--profile", options.profile, "--patch", overlay];
  if (options.sessionId) args.push("--session-id", options.sessionId);
  args.push(prompt);
  const result = await execa(process.execPath, [dshBinPath(), ...args], {
    cwd: scratch,
    reject: false,
    timeout: options.timeoutMs ?? 45 * 60_000,
    env: { ...process.env, PATH: toolPath(), ...TOOL_ENV },
    stdio: "pipe",
  });
  const stdout = `${result.stdout ?? ""}`;
  return {
    stdout,
    sessionId: firstSessionId(join(options.outDir, options.baseline, "review.jsonl"), stdout),
  };
}

export async function runDsh(options: RunOptions): Promise<{ stdout: string; sessionId: string | null }> {
  const scratch = join(options.outDir, "scratch", options.baseline);
  const prompt = options.correction ? CORRECTION_PROMPT : writePrompt(planCount(scratch));
  return runTask(options, prompt);
}

/**
 * A neutral forty-line module, generated here so the cost probe never touches a
 * dataset sample. It is not a benchmark of review quality - it is a
 * measurement of what one file costs, which is what the ceiling is about.
 */
const COST_PROBE_BODY = `export interface Row {
  id: string;
  kind: "alpha" | "beta";
  weight: number;
}

export interface Totals {
  alpha: number;
  beta: number;
  weight: number;
}

export function emptyTotals(): Totals {
  return { alpha: 0, beta: 0, weight: 0 };
}

export function addRow(totals: Totals, row: Row): Totals {
  const weight = Number.isFinite(row.weight) ? row.weight : 0;
  return row.kind === "alpha"
    ? { ...totals, alpha: totals.alpha + 1, weight: totals.weight + weight }
    : { ...totals, beta: totals.beta + 1, weight: totals.weight + weight };
}

export function summarize(rows: readonly Row[]): Totals {
  return rows.reduce(addRow, emptyTotals());
}

export function heaviest(rows: readonly Row[]): Row | null {
  let best: Row | null = null;
  for (const row of rows) {
    if (best === null || row.weight > best.weight) best = row;
  }
  return best;
}
`;

/**
 * What one file costs, measured. Runs `ocr scan` on the generated module and
 * reads `summary.total_tokens` out of the JSON envelope.
 *
 * It has to be a real request: a config read cannot tell a working key from an
 * exhausted quota, and the ceiling exists precisely to catch a run that would
 * spend its budget on failures.
 */
export async function probeAorCost(command = "ocr", budgetTokens = 60_000): Promise<NonNullable<RunEvidence["cost_probe"]>> {
  const dir = join(tmpdir(), `crs-aor-cost-probe-${Date.now()}`);
  await mkdir(dir, { recursive: true });
  await writeFile(join(dir, "probe.ts"), COST_PROBE_BODY, "utf8");
  const started = Date.now();
  const result = await execa(
    command,
    [
      "scan",
      "--path",
      "probe.ts",
      "--format",
      "json",
      "--no-summary",
      "--timeout",
      "2",
      "--max-tokens-budget",
      String(budgetTokens),
    ],
    { cwd: dir, env: { ...process.env, ...TOOL_ENV }, reject: false, timeout: 300_000 },
  );
  const elapsed = Date.now() - started;
  if (result.exitCode !== 0) {
    throw new Error(
      `cost probe failed in ${elapsed}ms: ${`${result.stderr ?? ""}`.trim().split("\n").slice(-3).join(" ").slice(-300)}`,
    );
  }
  let parsed: { summary?: { total_tokens?: unknown }; llm?: { model?: unknown } };
  try {
    parsed = JSON.parse(`${result.stdout ?? ""}`) as typeof parsed;
  } catch {
    throw new Error("cost probe did not return a JSON envelope");
  }
  const tokens = parsed.summary?.total_tokens;
  if (typeof tokens !== "number" || tokens <= 0) {
    throw new Error(`cost probe reported no token usage: ${String(tokens)}`);
  }
  return {
    tokens: Math.trunc(tokens),
    elapsed_ms: elapsed,
    file_lines: COST_PROBE_BODY.split("\n").length,
    model: typeof parsed.llm?.model === "string" ? parsed.llm.model : null,
    ran_at: new Date().toISOString(),
  };
}

/**
 * `probe x 2` because a reviewed write runs AOR twice (a preview pass and the
 * scan); `x 1.5` for the correction pass. It is an upper bound, not a forecast:
 * a bound that is too low would stop a run that is fine, which is the cheaper
 * mistake of the two.
 */
export function estimateCostTokens(probeTokens: number, rows: number): number {
  return Math.ceil(probeTokens * 2 * Math.max(1, rows) * 1.5);
}

/** A ceiling declared after the run started is not a ceiling. */
export function assertCostCeiling(estimate: number, ceiling: number): void {
  if (estimate > ceiling) {
    throw new Error(
      `refusing to start: the AOR cost probe implies up to ${estimate} tokens for this plan, ` +
        `above the declared ceiling of ${ceiling}. Raise the ceiling in ${PREREGISTRATION} ` +
        `deliberately, or stage fewer rows - not after seeing the result.`,
    );
  }
}

/**
 * Run directories that already used this dataset version.
 *
 * A run is identified by its `run.json`, which is written before any row
 * exists; a directory left without one was staged but never collected, and is
 * still named, so it still blocks by name.
 */
export async function existingEvalRuns(liveRoot: string, datasetVersion: string): Promise<string[]> {
  if (!existsSync(liveRoot)) return [];
  const found: string[] = [];
  for (const entry of await readdir(liveRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    if (!RUN_DIR_PATTERN.test(entry.name)) continue;
    if (!entry.name.startsWith("eval-")) continue;
    const manifestPath = join(liveRoot, entry.name, "run.json");
    if (!existsSync(manifestPath)) {
      found.push(entry.name);
      continue;
    }
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as { dataset_version?: unknown };
    if (manifest.dataset_version === datasetVersion) found.push(entry.name);
  }
  return found;
}

/**
 * The one-shot lock.
 *
 * The risk is not malice: it is "it crashed, fix it and run it again". A second
 * run that starts after the first result was seen is no longer blind, and
 * nothing about it looks different in the artefact. So a used dataset version
 * blocks until the operator names the reason and archives the old run; the
 * reason lands in the new `run.json`.
 */
export async function assertOneShot(
  outDir: string,
  datasetVersion: string,
  reason: string | null,
): Promise<OneShot["restarts"]> {
  const leaf = outDir.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "";
  const liveRoot = dirname(outDir);
  const used = await existingEvalRuns(liveRoot, datasetVersion);
  const blockers = [...new Set([...used, ...(existsSync(outDir) ? [leaf] : [])])];
  if (blockers.length === 0) return [];
  if (reason === null) {
    throw new Error(
      `refusing to start: dataset ${datasetVersion} was already measured by ${blockers.join(", ")}. ` +
        `A second run after the first result is no longer blind. If starting over is the decision, ` +
        `say why: --archive-and-restart="<reason>" (the old run is moved to runs/archive and the ` +
        `reason is written into the new run.json).`,
    );
  }
  const archiveRoot = join(dirname(liveRoot), "archive");
  await mkdir(archiveRoot, { recursive: true });
  const restarts: OneShot["restarts"] = [];
  for (const name of blockers) {
    const from = join(liveRoot, name);
    const to = join(archiveRoot, `${name}-${Date.now()}`);
    if (existsSync(from)) await rename(from, to);
    restarts.push({ archived: name, reason });
  }
  return restarts;
}

/** Per-row wall clock and tokens are already on the rows; this is the total. */
export async function recordActualCost(outDir: string): Promise<void> {
  const manifestPath = join(outDir, "run.json");
  if (!existsSync(manifestPath)) return;
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as RunManifest;
  let tokens = 0;
  let rows = 0;
  let missing = 0;
  let wall = 0;
  for (const baseline of ["B4", "B4g"] as const) {
    const jsonl = join(outDir, baseline, "review.jsonl");
    if (!existsSync(jsonl)) continue;
    for (const line of readFileSync(jsonl, "utf8").split("\n")) {
      if (line.trim().length === 0) continue;
      const row = JSON.parse(line) as ReviewRow;
      rows += 1;
      wall += row.latency_ms;
      if (typeof row.tokens === "number") tokens += row.tokens;
      else missing += 1;
    }
  }
  manifest.cost.actual = { tokens, rows, rows_without_tokens: missing, wall_ms: Math.round(wall) };
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
}

function planCount(scratch: string): number {
  const plan = JSON.parse(readFileSync(join(scratch, "plan.json"), "utf8")) as unknown[];
  return plan.length;
}

function firstSessionId(jsonl: string, _stdout: string): string | null {
  try {
    for (const line of readFileSync(jsonl, "utf8").split("\n")) {
      if (line.trim().length === 0) continue;
      const row = JSON.parse(line) as ReviewRow;
      return row.change_event.sessionId;
    }
  } catch {
    return null;
  }
  return null;
}

/** Convert plugin ReviewRows into the acceptance row shape. */
export function toAcceptanceRows(
  rows: readonly ReviewRow[],
  pathToSample: Map<string, string>,
  baseline: Baseline,
): AcceptanceRowLike[] {
  const out: AcceptanceRowLike[] = [];
  for (const row of rows) {
    const path = row.change_event.files?.[0];
    if (path === undefined) continue;
    const sample = pathToSample.get(path);
    if (sample === undefined) continue;
    out.push({
      sample,
      baseline,
      mode: row.mode,
      disposition: {
        preDecision: row.pre_decision,
        postDecision: row.post_decision,
        finalDisposition: row.final_disposition,
        text: row.text,
      },
      findings_merged: row.findings_merged.map((finding) => ({
        file: finding.file,
        startLine: finding.startLine,
        endLine: finding.endLine,
        cwe: finding.cwe,
      })),
      sources: row.sources.map((source) => ({
        source: source.source,
        status: source.status,
        errorKind: source.errorKind ?? null,
        findings: source.findings.map((finding) => ({
          file: finding.file,
          cwe: finding.cwe,
          evidence: finding.evidence,
        })),
      })),
      tokens: row.tokens,
      latency_ms: row.latency_ms,
      change_event: { sessionId: row.change_event.sessionId, ts: row.change_event.ts, phase: row.change_event.phase },
      review_skip_reason: row.review_skip_reason,
      tier: row.tier,
      tier_source: row.tier_source,
      // Carried through untouched: the acceptance report must be able to refuse
      // a run whose binaries are not the frozen ones, and a consumer that
      // re-derives this could silently "fix" the drift it is meant to catch.
      instrument: row.instrument,
    } as AcceptanceRowLike);
  }
  return out;
}

export async function collect(plan: DrillPlan, outDir: string, datasetDir: string): Promise<void> {
  readRunManifest(outDir, datasetDir);
  const pathToSample = new Map<string, string>();
  for (const sample of allSamples(plan)) pathToSample.set(sample.path, sample.sampleId);
  const all: AcceptanceRowLike[] = [];
  for (const baseline of ["B4", "B4g"] as const) {
    const jsonl = join(outDir, baseline, "review.jsonl");
    if (!existsSync(jsonl)) continue;
    const rows: ReviewRow[] = [];
    for (const line of (await readFile(jsonl, "utf8")).split("\n")) {
      if (line.trim().length === 0) continue;
      rows.push(JSON.parse(line) as ReviewRow);
    }
    all.push(...toAcceptanceRows(rows, pathToSample, baseline));
  }
  await writeFile(join(outDir, "rows.jsonl"), all.map((row) => JSON.stringify(row)).join("\n") + "\n", "utf8");
}

export async function evaluate(
  outDir: string,
  datasetDir: string,
  gapsPath: string,
  acceptanceOut: string,
  coverage: RuleCoverage,
): Promise<{ pass: number; lines: Array<{ name: string; pass: boolean; detail: string }> }> {
  // The run directory names its dataset and its pin; both are checked before any
  // number is printed, and `evaluateAcceptance` refuses a drifted instrument.
  const run = readRunManifest(outDir, datasetDir);
  // The binary is the instrument underneath the instrument. A run whose `ocr`
  // changed between the first and the last row has numbers from two rulers and
  // no way to say which row came from which; a run with no closing observation
  // has no way to say it did not.
  const identity = run.ocr_identity;
  if (identity !== undefined && identity !== null) {
    if (identity.drifted) {
      throw new Error(
        `refusing to evaluate: instrument_drifted - ${outDir} was measured across two different ` +
          `\`ocr\` binaries\n` +
          `  before: ${identity.before?.version ?? "?"} sha256 ${identity.before?.sha256 ?? "?"}\n` +
          `  after:  ${identity.after?.version ?? "?"} sha256 ${identity.after?.sha256 ?? "?"}`,
      );
    }
    if (identity.before !== null && identity.after === null) {
      throw new Error(
        `refusing to evaluate: ${outDir} has no post-run \`ocr\` identity, so its rows cannot be ` +
          `attributed to the binary that produced them (instrument_drifted unproven, not absent)`,
      );
    }
  }
  // A pin edited after the run was staged is the same failure as a pin that was
  // never frozen: the goalposts moved between the measurement and the report.
  // The run carries its own copy, so this compares two records, not a record
  // with a memory.
  const now = loadFrozenPin();
  if (JSON.stringify(run.frozen_instruments) !== JSON.stringify(now)) {
    throw new Error(
      `refusing to evaluate: ${PREREGISTRATION} changed after ${outDir} was staged\n` +
        `  run:  ${JSON.stringify(run.frozen_instruments)}\n` +
        `  now:  ${JSON.stringify(now)}`,
    );
  }
  // Only the collected acceptance rows. `B4/review.jsonl` is the plugin's own
  // shape (one row per phase, `pre_decision` not `disposition`); reading the
  // whole tree mixed the two shapes and crashed on the first plugin row.
  const rowsPath = join(outDir, "rows.jsonl");
  if (!existsSync(rowsPath)) {
    throw new Error(`${rowsPath} is missing: run --stage collect before --stage evaluate`);
  }
  const rows: AcceptanceRowLike[] = [];
  for (const line of (await readFile(rowsPath, "utf8")).split("\n")) {
    if (line.trim().length === 0) continue;
    rows.push(JSON.parse(line) as AcceptanceRowLike);
  }
  const gaps = existsSync(gapsPath) ? JSON.parse(await readFile(gapsPath, "utf8")) : null;
  // The staging projection promised A: tier 0 and B: tier >= 1. If a row lands
  // somewhere else during the run, the tier fell back to the static ladder,
  // AOR never saw that file, and the contingency table would report it as a
  // miss. That is a measurement failure wearing a detection failure's clothes.
  const projection = run.evidence?.strata_projection ?? null;
  if (projection === null) {
    throw new Error(
      `refusing to evaluate: ${outDir} has no strata projection. The run was staged without an ` +
        `index, so nothing says which rows were above the tier boundary and nothing can check it.`,
    );
  }
  const stratumOf = new Map(projection.rows.map((row) => [row.sample_id, row.stratum]));
  const posted = rows.filter((row) => row.change_event?.phase === "post" && stratumOf.has(row.sample));
  const wrong = posted.filter((row) =>
    stratumOf.get(row.sample) === "B" ? (row.tier ?? 0) < 1 : row.tier !== 0,
  );
  if (wrong.length > 0) {
    throw new Error(
      `refusing to evaluate: ${wrong.length} row(s) left their stratum at run time ` +
        `(${wrong
          .map((row) => `${row.sample} tier ${row.tier ?? "?"} via ${row.tier_source ?? "?"}`)
          .join(", ")}). ` +
        `A positive below tier 1 never reached AOR; a negative above tier 0 removes line 4's ` +
        `denominator. Re-stage with a crgQueryMs that the graph actually meets.`,
    );
  }
  const withAor = new Set(posted.filter((row) => (row.tier ?? 0) >= 1).map((row) => row.sample));
  const unreviewed = projection.rows.filter((row) => row.stratum === "B" && !withAor.has(row.sample_id));
  if (unreviewed.length > 0) {
    process.stdout.write(
      `WARN ${unreviewed.length} positive row(s) have no post-phase row at tier >= 1: ` +
        `${unreviewed.map((row) => row.sample_id).join(", ")} - the driver wrote nothing for them, ` +
        `so they are missing from the denominator rather than counted as misses\n`,
    );
  }
  const report = evaluateAcceptance(rows, await loadTruth(datasetDir), gaps, {
    coverage,
    frozenInstruments: run.frozen_instruments,
  });
  await mkdir(acceptanceOut, { recursive: true });
  await writeFile(join(acceptanceOut, "report.md"), `# 验收结果表（${report.mode}）\n\n${report.resultsTable}\n`, "utf8");
  await writeFile(join(acceptanceOut, "verdict.md"), report.verdict, "utf8");
  await writeFile(
    join(acceptanceOut, "verdict.json"),
    `${JSON.stringify(report.lines.map(({ name, pass, metrics }) => ({ name, pass, metrics })), null, 2)}\n`,
    "utf8",
  );
  return {
    pass: report.lines.filter((line) => line.pass).length,
    lines: report.lines.map(({ name, pass, detail }) => ({ name, pass, detail })),
  };
}

/**
 * Gates that protect the one-shot measurement. They have no `--allow-degraded`
 * bypass: a degraded instrument, dataset, plugin bundle or API key produces
 * numbers that look finished and cannot be reproduced. Other gates (a missing
 * optional tool, a warning-only scan) may be waived one name at a time with
 * `--allow-degraded=<gate>[,<gate>]`.
 *
 * `plugin bundle` is the fourth: the rows are written by `dist/plugin.js`, so a
 * bundle older than `src/` measures the previous version of the system and its
 * rows are in a shape the evaluator refuses - discovered after the eval is spent.
 *
 * `aor model`, `frozen pin` and `secret not tracked` joined it later. The first
 * two are the same class as `ocr pin` (identity, one level deeper and one level
 * earlier); the third keeps a short-lived credential out of a public tree, which
 * is not a judgement call to waive. A gate that protects the measurement must
 * not have a side door - the failure it prevents is invisible in the artefact.
 *
 * `ocr updater` is the same argument taken one step further: `ocr pin` observes
 * whether the binary moved, this one removes the thing that moves it. A check
 * that can only report a drift after the one blind run has been spent is not a
 * protection; the file has to be gone before the window opens.
 */
export const NON_DEGRADABLE_GATES = [
  "ocr pin",
  "ocr updater",
  "calibration artifact",
  "DEEPSEEK_API_KEY",
  "plugin bundle",
  "aor model",
  "frozen pin",
  "crg budget",
  "secret not tracked",
] as const;

export function parseDegradedGates(argv: readonly string[], known: readonly string[]): string[] {
  const values: string[] = [];
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index]!;
    if (entry === "--allow-degraded") {
      throw new Error(
        "`--allow-degraded` needs the gate names it waives: --allow-degraded=<gate>[,<gate>]",
      );
    }
    if (!entry.startsWith("--allow-degraded=")) continue;
    const value = entry.slice("--allow-degraded=".length);
    if (value.trim().length === 0) throw new Error("`--allow-degraded=` carries no gate name");
    values.push(...value.split(",").map((name) => name.trim()).filter((name) => name.length > 0));
  }
  const unique = [...new Set(values)];
  for (const name of unique) {
    if ((NON_DEGRADABLE_GATES as readonly string[]).includes(name)) {
      throw new Error(`gate "${name}" protects the measurement and can never be degraded`);
    }
    if (!known.includes(name)) {
      throw new Error(`unknown gate "${name}": pass one of ${known.join(", ")}`);
    }
  }
  return unique;
}

/**
 * A flag that must carry a value. `--allow-eval` and `--archive-and-restart`
 * are decisions; a bare flag is not one, and silently treating it as "yes" is
 * how a second run starts without anyone deciding to have one.
 */
export function flagValue(argv: readonly string[], name: string): string | null {
  let found: string | null = null;
  for (let index = 0; index < argv.length; index += 1) {
    const entry = argv[index]!;
    if (entry === name) {
      const next = argv[index + 1];
      if (next === undefined || next.startsWith("--") || next.trim().length === 0) {
        throw new Error(`${name} needs a value`);
      }
      found = next;
      continue;
    }
    if (entry.startsWith(`${name}=`)) {
      const value = entry.slice(name.length + 1).trim();
      if (value.length === 0) throw new Error(`${name}= carries no value`);
      found = value;
    }
  }
  return found;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const allowEval = flagValue(argv, "--allow-eval");
  const restartReason = flagValue(argv, "--archive-and-restart");
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const baseConfig = resolve(arg("--config", "configs/b4.json"));
  const profile = arg("--profile", "crs-live");
  const stage = arg("--stage", "all");
  const acceptanceOut = resolve(arg("--acceptance-out", "artifacts/acceptance"));
  const liveRoot = resolve(arg("--live-root", "runs/live"));
  const plan = planDrill(datasetDir, { rulesTablePath: resolve(arg("--rules", RULES_TABLE)) });
  const ruleset = pinnedTsRuleset(baseConfig);
  const aorCommit = pinnedAorCommit(baseConfig);
  const coverage: RuleCoverage = { language: plan.coverage.language, perCwe: plan.coverage.declared };
  const isEvalStage = stage === "prepare" || stage === "all";
  if (isEvalStage && allowEval === null) {
    throw new Error(
      "refusing to stage an eval run without --allow-eval=<run name>: the name is the one-shot " +
        "token (it is recorded in run.json), and a run that can start by accident is not one-shot",
    );
  }

  process.stdout.write(
    `dataset: ${plan.datasetVersion}\n` +
      `plan: ${plan.positives.length} positives, ${plan.lowRisk.length} low-risk ` +
      `(${plan.lowRisk.filter((sample) => sample.eventKind === "create").length} create), ` +
      `${plan.controls.length} controls, 1 probe ` +
      `(rules ${ruleset}, ${plan.coverage.language})\n` +
      `coverage declared: ${Object.entries(plan.coverage.declared)
        .map(([cwe, count]) => `${cwe}=${count}`)
        .join(" ")}\n` +
      plan.warnings.map((warning) => `WARN ${warning}\n`).join(""),
  );

  // The change event is one file (the host's write tool takes one path), so the
  // tier cannot come from the change size. It comes from the repository: each
  // positive is staged with three clean importers, which the graph reports as a
  // four-file blast radius, and each negative stays alone. Staging projects both
  // strata and refuses to start if either is wrong.
  const tier0 = (JSON.parse(readFileSync(baseConfig, "utf8")) as { triage: { tier0: { filesMax: number } } })
    .triage.tier0.filesMax;
  if (tier0 >= 1) {
    process.stdout.write(
      `NOTE one change event is one file, so the tier comes from the staged repository: each ` +
        `positive carries ${IMPORTERS_PER_POSITIVE} clean importers (blast radius ` +
        `${IMPORTERS_PER_POSITIVE + 1} > triage.tier0.filesMax=${tier0} -> tier 1) and each negative ` +
        `stays a single file (tier 0). Staging projects every row's tier and refuses to start ` +
        `otherwise.\n`,
    );
  }

  // Every stage but `check` needs a named run directory: an unnamed one is how
  // the ds-1 staging ended up sitting next to the ds-2 run. For an eval run the
  // name is also the one-shot token, so it comes from `--allow-eval`.
  const explicit = arg("--out", "");
  const wantsRunDir = stage !== "check";
  let outDir = explicit.length > 0 ? resolve(explicit) : "";
  if (wantsRunDir && allowEval !== null) {
    assertRunDir(allowEval);
    const byName = join(liveRoot, allowEval);
    if (outDir.length > 0 && resolve(outDir) !== resolve(byName)) {
      throw new Error(`--out ${outDir} and --allow-eval=${allowEval} name different runs`);
    }
    outDir = byName;
  }
  if (wantsRunDir && outDir.length === 0 && argv.includes("--new-run")) {
    outDir = newRunDir(liveRoot, plan.datasetVersion, stage === "smoke" ? "smoke" : "eval");
  }
  if (wantsRunDir) {
    if (outDir.length === 0) {
      throw new Error(
        `--stage ${stage} needs --out=<named run dir> or --allow-eval=<run name>; ` +
          `a name looks like eval-${plan.datasetVersion}-<yyyyMMddTHHmmss>`,
      );
    }
    assertRunDir(outDir);
    process.stdout.write(`run dir: ${outDir}\n`);
  }

  if (stage === "check") {
    const result = await preflight(profile, {
      plan,
      ruleset,
      datasetDir,
      aorCommit,
      baseConfig,
      frozen: loadFrozenPin(),
    });
    process.stdout.write(
      `${result.checks.map((check) => `${check.ok ? "OK  " : "FAIL"} ${check.name} :: ${check.detail}`).join("\n")}\n`,
    );
    if (!result.ok) process.exitCode = 2;
    return;
  }
  if (stage === "smoke") {
    await stageDrill({
      datasetDir,
      outDir,
      baseConfig,
      profile,
      plan,
      frozen: loadFrozenPin(),
      evidence: {
        bundle: null,
        aor_probe: null,
        cost_probe: null,
        cost_estimate: null,
        strata_projection: null,
        wall_clock_estimate: null,
      },
      oneShot: { run: outDir.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "", at: new Date().toISOString(), restarts: [] },
    });
    const first = plan.positives[0]!;
    const run = await runTask(
      { outDir, profile, baseline: "B4", timeoutMs: 10 * 60_000 },
      `Read ${first.staged} and write its exact text to ${first.path} using the write tool. Do not use the shell. Reply exactly DONE.`,
    );
    process.stdout.write(`smoke: ${run.stdout.trim().slice(-200)}\n`);
    const jsonl = join(outDir, "B4", "review.jsonl");
    if (existsSync(jsonl)) {
      for (const line of readFileSync(jsonl, "utf8").split("\n")) {
        if (line.trim().length === 0) continue;
        const row = JSON.parse(line) as ReviewRow;
        if (row.change_event.files?.[0] !== first.path) continue;
        process.stdout.write(
          `${row.change_event.phase} mode=${row.mode} tier=${row.tier} pre=${row.pre_decision} post=${row.post_decision} ` +
            `status=${row.review_status} sources=${row.sources.map((s) => `${s.source}:${s.status}:${s.findings.length}`).join(",")} ` +
            `instrument=${row.instrument.semgrep.version}/${row.instrument.ocr.version}(${row.instrument.ocr.commit ?? "none"}) ` +
            `model=${row.instrument.aor_model.id}\n`,
        );
      }
    }
    return;
  }
  if (isEvalStage) {
    const frozen = loadFrozenPin();
    const ready = await preflight(profile, { plan, ruleset, datasetDir, aorCommit, baseConfig, frozen });
    const known = ready.checks.map((check) => check.name);
    const allow = parseDegradedGates(process.argv, known);
    const waived = ready.checks.filter((check) => !check.ok && allow.includes(check.name));
    const blocking = ready.checks.filter((check) => !check.ok && !allow.includes(check.name));
    if (waived.length > 0) {
      process.stdout.write(
        `DEGRADED (waived by name): ${waived.map((check) => check.name).join(", ")}\n`,
      );
    }
    if (blocking.length > 0) {
      process.stdout.write(
        `${ready.checks.map((check) => `${check.ok ? "OK  " : "FAIL"} ${check.name} :: ${check.detail}`).join("\n")}\n`,
      );
      throw new Error(
        `preflight failed: ${blocking.map((check) => check.name).join(", ")}; ` +
          `only a non-blocking gate may be waived, and only by name (--allow-degraded=<gate>)`,
      );
    }
    // Cost before the one-shot lock: the ceiling check is the last thing that
    // can still refuse without having touched anything, and archiving an old
    // run for a run that then fails its own budget would destroy evidence.
    const costProbe = await probeAorCost();
    ready.evidence.cost_probe = costProbe;
    const rows = 2 * allSamples(plan).length;
    const ceiling = loadCostCeiling();
    const estimate = estimateCostTokens(costProbe.tokens, rows);
    assertCostCeiling(estimate, ceiling);
    ready.evidence.cost_estimate = {
      tokens: estimate,
      ceiling_tokens: ceiling,
      rows,
      probe_tokens: costProbe.tokens,
      method:
        "probe tokens x 2 (preview + scan) x staged rows x 1.5 (correction headroom); " +
        "an upper bound on AOR spend, not a prediction of the driver's tokens",
    };
    process.stdout.write(
      `cost: probe ${costProbe.tokens} tokens/${costProbe.file_lines} lines in ${costProbe.elapsed_ms}ms ` +
        `-> up to ${estimate} tokens for ${rows} rows (ceiling ${ceiling})\n`,
    );
    // Wall clock, from the caps the pre path can spend plus the one AOR call
    // that was actually measured. The AOR term is a 38-line file, so the total
    // is a floor for the AOR part and a ceiling for everything else; the index
    // build is measured at staging time and added there.
    const budgets = (JSON.parse(readFileSync(baseConfig, "utf8")) as { budgets: Record<string, number> })
      .budgets;
    const perRowMs =
      (budgets["semgrepKillMs"] ?? 0) + (budgets["crgQueryMs"] ?? 0) + costProbe.elapsed_ms;
    const wall = {
      rows,
      per_row_ms: perRowMs,
      total_ms: rows * perRowMs,
      index_build_ms: 0,
      components: {
        semgrep_ms: budgets["semgrepKillMs"] ?? 0,
        crg_ms: budgets["crgQueryMs"] ?? 0,
        aor_ms: costProbe.elapsed_ms,
        basis: "caps for semgrep and crg, one measured ocr call for aor; index build added at staging",
      },
    };
    ready.evidence.wall_clock_estimate = wall;
    process.stdout.write(
      `wall clock: ${rows} rows x (semgrep ${wall.components.semgrep_ms}ms + crg ${wall.components.crg_ms}ms ` +
        `+ aor ${wall.components.aor_ms}ms) = ${(wall.total_ms / 60_000).toFixed(1)} min ` +
        `(plus graph builds, plus the driver's own turns)\n`,
    );
    const restarts = await assertOneShot(outDir, plan.datasetVersion, restartReason);
    if (restarts.length > 0) {
      process.stdout.write(
        `archived: ${restarts.map((entry) => `${entry.archived} (${entry.reason})`).join(", ")}\n`,
      );
    }
    await stageDrill({
      datasetDir,
      outDir,
      baseConfig,
      profile,
      plan,
      degradedGates: waived.map((check) => check.name),
      frozen,
      evidence: ready.evidence,
      oneShot: {
        run: outDir.replace(/[\\/]+$/, "").split(/[\\/]/).pop() ?? "",
        at: new Date().toISOString(),
        restarts,
      },
    });
    process.stdout.write(`staged ${allSamples(plan).length} files per baseline in ${outDir}\n`);
  }
  if (stage === "run" || stage === "all") {
    if (!process.env["DEEPSEEK_API_KEY"]) {
      throw new Error("DEEPSEEK_API_KEY is required to run live agent sessions");
    }
    readRunManifest(outDir, datasetDir);
    // Two observations bracket the window, because `ocr` updates itself from a
    // detached child: a single check before the run cannot see a swap that lands
    // during it, and a single check after cannot say when it happened.
    const before = await recordOcrIdentity(outDir, "before");
    for (const baseline of ["B4", "B4g"] as const) {
      process.stdout.write(`running ${baseline}...\n`);
      const write = await runDsh({ outDir, profile, baseline, timeoutMs: 45 * 60_000 });
      process.stdout.write(`${baseline} write pass: ${write.stdout.trim().slice(-200)}\n`);
      if (write.sessionId) {
        const fix = await runDsh({
          outDir,
          profile,
          baseline,
          correction: true,
          sessionId: write.sessionId,
          timeoutMs: 20 * 60_000,
        });
        process.stdout.write(`${baseline} correction pass: ${fix.stdout.trim().slice(-200)}\n`);
      }
    }
    // Recorded, never enforced here: aborting mid-run would leave a half
    // dataset and spend the blind run anyway. `evaluate` is where a drifted
    // binary stops the numbers from being printed.
    const after = await recordOcrIdentity(outDir, "after");
    process.stdout.write(
      `ocr before: ${before.before?.version ?? "?"} sha256 ${before.before?.sha256?.slice(0, 12) ?? "unresolved"}\n` +
        `ocr after:  ${after.after?.version ?? "?"} sha256 ${after.after?.sha256?.slice(0, 12) ?? "unresolved"}` +
        `${after.drifted ? " - INSTRUMENT DRIFTED" : ""}\n`,
    );
    await recordActualCost(outDir);
  }
  if (stage === "collect" || stage === "all") {
    await collect(plan, outDir, datasetDir);
  }
  if (stage === "evaluate" || stage === "all") {
    const result = await evaluate(
      outDir,
      datasetDir,
      resolve(arg("--gaps", "artifacts/block-gaps.json")),
      acceptanceOut,
      coverage,
    );
    process.stdout.write(
      `${result.lines.map((line) => `${line.pass ? "PASS" : "FAIL"} ${line.name} :: ${line.detail}`).join("\n")}\n`,
    );
    process.stdout.write(`acceptance: ${result.pass}/5\n`);
    if (result.pass < 5) process.exitCode = 3;
  }
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/live-drill.ts")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
