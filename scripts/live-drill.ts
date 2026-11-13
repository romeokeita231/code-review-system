import { execa } from "execa";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdir, readdir, readFile, stat, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Baseline, Mode, ReviewRow } from "../src/contracts/index.js";
import { calibrationCategories } from "../src/contracts/index.js";
import { assertCalibrationMatches, loadCalibration, sha256, TOOL_ENV } from "../src/config/index.js";
import { loadDataset, type DatasetSample } from "../src/l5/replay.js";
import { evaluateAcceptance, labelSpansOf, loadTruth, type AcceptanceRowLike, type RuleCoverage } from "./acceptance.js";
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

  // Defect-free rows that line 4 did not take. With eight low-risk negatives
  // this is empty by construction: the low-risk pool *is* the precision
  // denominator, and `evaluateAcceptance` counts it from the ground truth, not
  // from this list.
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
function labelsOf(file: Record<string, unknown>): Array<{ path: string; startLine: number; endLine: number; cwe: string | null }> {
  return labelSpansOf(file);
}

function loadDatasetSync(datasetDir: string, requestedLanguage?: string): LoadedDataset {
  // loadDataset is async; the plan is pure so callers can plan before any
  // staging. Keep one synchronous read path for determinism.
  const manifest = JSON.parse(readFileSync(join(datasetDir, "manifest.json"), "utf8")) as {
    version?: string;
    samples: Array<Record<string, unknown> & { sample_id: string }>;
  };
  const version = typeof manifest.version === "string" ? manifest.version : "";
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
}

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

export interface RunManifest {
  dataset_version: string;
  dataset_dir: string;
  config_hash: string;
  /** The pin the numbers must be reproduced against. */
  frozen_instruments: { semgrep: { version: string }; ocr: { commit: string } };
  created_at: string;
  plan: { positives: number; low_risk: number; controls: number; probe: number; negatives_create: number };
  degraded_gates: string[];
}

/** The pin, read from the config the run claims to use. */
export function frozenInstrumentsOf(baseConfig: string): RunManifest["frozen_instruments"] {
  const base = JSON.parse(readFileSync(baseConfig, "utf8")) as {
    sources?: { semgrep?: { version?: string }; aor?: { versionCommit?: string } };
  };
  return {
    semgrep: { version: base.sources?.semgrep?.version ?? "" },
    ocr: { commit: base.sources?.aor?.versionCommit ?? "" },
  };
}

async function writeRunManifest(options: StageOptions): Promise<RunManifest> {
  const manifest: RunManifest = {
    dataset_version: options.plan.datasetVersion,
    dataset_dir: resolve(options.datasetDir),
    config_hash: sha256(await readFile(options.baseConfig, "utf8")),
    frozen_instruments: frozenInstrumentsOf(options.baseConfig),
    created_at: new Date().toISOString(),
    plan: {
      positives: options.plan.positives.length,
      low_risk: options.plan.lowRisk.length,
      controls: options.plan.controls.length,
      probe: 1,
      negatives_create: options.plan.lowRisk.filter((sample) => sample.eventKind === "create").length,
    },
    degraded_gates: [...(options.degradedGates ?? [])],
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
export async function stageDrill(options: StageOptions): Promise<void> {
  assertRunDir(options.outDir);
  const base = JSON.parse(await readFile(options.baseConfig, "utf8")) as Record<string, unknown>;
  const samples = allSamples(options.plan);

  for (const baseline of ["B4", "B4g"] as const) {
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
    };
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
}

export interface PreflightOptions {
  plan?: DrillPlan;
  /** Ruleset the baseline config actually loads for TypeScript. */
  ruleset?: string;
  datasetDir?: string;
  /** Commit the AOR numbers must come from; empty means the pin is not asserted. */
  aorCommit?: string;
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

export async function preflight(profile: string, options: PreflightOptions = {}): Promise<Preflight> {
  const checks: Preflight["checks"] = [];
  const env = { ...process.env, PATH: toolPath(), ...TOOL_ENV };

  const run = async (name: string, file: string, args: string[], cwd = process.cwd()) => {
    const result = await execa(file, args, { cwd, env, reject: false, timeout: 120_000 });
    const output = `${result.stdout ?? ""}${result.stderr ?? ""}`.trim();
    checks.push({
      name,
      ok: result.exitCode === 0,
      detail: result.exitCode === 0 ? output.split("\n")[0] ?? "" : output.slice(-400),
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
    checks.push({
      name: "ocr pin",
      ok: matches,
      detail: matches
        ? text
        : `${text} - config pins ${options.aorCommit}; re-pin before quoting AOR numbers`,
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
  try {
    const bundle = resolve("dist/plugin.js");
    if (!existsSync(bundle)) throw new Error("dist/plugin.js is missing: run `npm run build`");
    const bundleMtime = (await stat(bundle)).mtimeMs;
    const newest = await newestSource("src");
    if (newest === null) throw new Error("no sources under src/ to compare against");
    if (newest.at > bundleMtime) {
      throw new Error(`${newest.path} is newer than dist/plugin.js: run \`npm run build\``);
    }
    checks.push({ name: "plugin bundle", ok: true, detail: `dist/plugin.js covers ${newest.path}` });
  } catch (error) {
    checks.push({
      name: "plugin bundle",
      ok: false,
      detail: (error as Error).message.slice(-400),
    });
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
  return { ok: checks.every((check) => check.ok), checks };
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
  const report = evaluateAcceptance(rows, await loadTruth(datasetDir), gaps, {
    coverage,
    frozenInstruments: run.frozen_instruments,
  });
  await mkdir(acceptanceOut, { recursive: true });
  await writeFile(join(acceptanceOut, "report.md"), `# 楠屾敹缁撴灉琛紙${report.mode}锛塡n\n${report.resultsTable}\n`, "utf8");
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
 */
export const NON_DEGRADABLE_GATES = [
  "ocr pin",
  "calibration artifact",
  "DEEPSEEK_API_KEY",
  "plugin bundle",
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

async function main(): Promise<void> {
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const baseConfig = resolve(arg("--config", "configs/b4.json"));
  const profile = arg("--profile", "crs-live");
  const stage = arg("--stage", "all");
  const acceptanceOut = resolve(arg("--acceptance-out", "artifacts/acceptance"));
  const plan = planDrill(datasetDir, { rulesTablePath: resolve(arg("--rules", RULES_TABLE)) });
  const ruleset = pinnedTsRuleset(baseConfig);
  const aorCommit = pinnedAorCommit(baseConfig);
  const coverage: RuleCoverage = { language: plan.coverage.language, perCwe: plan.coverage.declared };

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

  // Every stage but `check` needs a named run directory: an unnamed one is how
  // the ds-1 staging ended up sitting next to the ds-2 run.
  const explicit = arg("--out", "");
  const wantsRunDir = stage !== "check";
  let outDir = explicit.length > 0 ? resolve(explicit) : "";
  if (wantsRunDir && process.argv.includes("--new-run")) {
    outDir = newRunDir(resolve(arg("--live-root", "runs/live")), plan.datasetVersion, stage === "smoke" ? "smoke" : "eval");
  }
  if (wantsRunDir) {
    if (outDir.length === 0) {
      throw new Error(
        `--stage ${stage} needs --out=<named run dir> or --new-run; ` +
          `a name looks like eval-${plan.datasetVersion}-<yyyyMMddTHHmmss>`,
      );
    }
    assertRunDir(outDir);
    process.stdout.write(`run dir: ${outDir}\n`);
  }

  if (stage === "check") {
    const result = await preflight(profile, { plan, ruleset, datasetDir, aorCommit });
    process.stdout.write(
      `${result.checks.map((check) => `${check.ok ? "OK  " : "FAIL"} ${check.name} :: ${check.detail}`).join("\n")}\n`,
    );
    if (!result.ok) process.exitCode = 2;
    return;
  }
  if (stage === "smoke") {
    await stageDrill({ datasetDir, outDir, baseConfig, profile, plan });
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
          `${row.change_event.phase} mode=${row.mode} pre=${row.pre_decision} post=${row.post_decision} ` +
            `status=${row.review_status} sources=${row.sources.map((s) => `${s.source}:${s.status}:${s.findings.length}`).join(",")} ` +
            `instrument=${row.instrument.semgrep.version}/${row.instrument.ocr.version}(${row.instrument.ocr.commit ?? "none"})\n`,
        );
      }
    }
    return;
  }
  if (stage === "prepare" || stage === "all") {
    const ready = await preflight(profile, { plan, ruleset, datasetDir, aorCommit });
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
    await stageDrill({
      datasetDir,
      outDir,
      baseConfig,
      profile,
      plan,
      degradedGates: waived.map((check) => check.name),
    });
    process.stdout.write(`staged ${allSamples(plan).length} files per baseline in ${outDir}\n`);
  }
  if (stage === "run" || stage === "all") {
    if (!process.env["DEEPSEEK_API_KEY"]) {
      throw new Error("DEEPSEEK_API_KEY is required to run live agent sessions");
    }
    readRunManifest(outDir, datasetDir);
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
