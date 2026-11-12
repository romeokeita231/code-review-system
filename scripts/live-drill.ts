import { execa } from "execa";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { Baseline, Mode, ReviewRow } from "../src/contracts/index.js";
import { loadDataset, type DatasetSample } from "../src/l5/replay.js";
import { collectJsonl, evaluateAcceptance, loadTruth, type AcceptanceRowLike } from "./acceptance.js";
import { arg } from "./shared.js";

export interface PlannedSample {
  sampleId: string;
  /** Repo-relative POSIX path, as the plugin records it. */
  path: string;
  /** Staged text the agent copies verbatim. */
  staged: string;
  kind: "positive" | "low-risk" | "dep-probe";
}

export interface DrillPlan {
  positives: PlannedSample[];
  lowRisk: PlannedSample[];
  probe: PlannedSample;
}

export const DEP_PROBE: PlannedSample = {
  sampleId: "dep-hallucination-01",
  path: "live/dep-hallucination-01/package.json",
  staged: ".staging/dep-hallucination-01.txt",
  kind: "dep-probe",
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

/**
 * The live set is the spec's 20 injection posamples plus its separate 8
 * low-risk samples and one dependency-hallucination probe. Line 1 needs n>=20
 * semgrep-detectable eval positives, and line 4 needs those same 8 low-risk
 * samples present for B4/B4g pairing, so they cannot be folded into the 20.
 */
export function planDrill(datasetDir: string, limitPositives = 20, lowRiskCount = 8): DrillPlan {
  const loaded = loadDatasetSync(datasetDir);
  const detectable = loaded.samples.filter(
    (sample) =>
      sample.split === "eval" &&
      sample.labels.length > 0 &&
      sample.expected_detectable_by.includes("semgrep"),
  );
  if (detectable.length < limitPositives) {
    throw new Error(
      `dataset has ${detectable.length} semgrep-detectable eval positives, needs ${limitPositives}`,
    );
  }
  const positives = detectable
    .slice()
    .sort((a, b) => a.sample_id.localeCompare(b.sample_id))
    .slice(0, limitPositives)
    .map((sample) => ({
      sampleId: sample.sample_id,
      path: livePath(sample),
      staged: stagedOf(sample),
      kind: "positive" as const,
    }));
  const chosen = new Set(positives.map((sample) => sample.sampleId));
  const lowRisk = loaded.samples
    .filter((sample) => sample.risk_level === "low" && !chosen.has(sample.sample_id))
    .slice(0, lowRiskCount)
    .map((sample) => ({
      sampleId: sample.sample_id,
      path: livePath(sample),
      staged: stagedOf(sample),
      kind: "low-risk" as const,
    }));
  if (lowRisk.length < lowRiskCount) {
    throw new Error(`dataset has only ${lowRisk.length} spare low-risk samples, needs ${lowRiskCount}`);
  }
  return { positives, lowRisk, probe: { ...DEP_PROBE, staged: DEP_PROBE.staged } };
}

function loadDatasetSync(datasetDir: string): { samples: DatasetSample[] } {
  // loadDataset is async; the plan is pure so callers can plan before any
  // staging. Keep one synchronous read path for determinism.
  const manifest = JSON.parse(readFileSync(join(datasetDir, "manifest.json"), "utf8")) as {
    samples: Array<{ sample_id: string }>;
  };
  const samples = manifest.samples.map((entry) =>
    JSON.parse(readFileSync(join(datasetDir, "samples", `${entry.sample_id}.json`), "utf8")),
  ) as DatasetSample[];
  return { samples };
}

export function allSamples(plan: DrillPlan): PlannedSample[] {
  return [...plan.positives, ...plan.lowRisk, plan.probe];
}

export interface StageOptions {
  datasetDir: string;
  outDir: string;
  baseConfig: string;
  profile: string;
  plan: DrillPlan;
}

/** Materialise the scratch repos, configs and profile overlays for one run. */
export async function stageDrill(options: StageOptions): Promise<void> {
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

/**
 * Fail fast, and for the right reason. Semgrep in particular can be installed
 * yet crash before rule matching (`CertOpenSystemStore returned NULL` in its
 * OCaml CA bootstrap), which otherwise only surfaces as a degraded scan.
 */
export async function preflight(profile: string): Promise<Preflight> {
  const checks: Preflight["checks"] = [];
  const env = { ...process.env, PATH: toolPath() };

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
  await run("code-review-graph", "code-review-graph", ["--help"]);
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
  } else {
    const sampleHits = await semgrepDetectable(5);
    checks.push({
      name: "dataset semgrep detectability",
      ok: sampleHits.hits > 0,
      detail:
        `${sampleHits.hits}/${sampleHits.scanned} planned positives match the pinned ruleset` +
        (sampleHits.hits === 0
          ? " - expected_detectable_by claims semgrep, so line1 cannot pass until the dataset or the annotation changes"
          : ""),
    });
  }
  return { ok: checks.every((check) => check.ok), checks };
}

/** Scan the first planned positives with the pinned full ruleset. */
async function semgrepDetectable(limit: number): Promise<{ hits: number; scanned: number }> {
  const plan = planDrill("datasets/self-built");
  const dir = join(tmpdir(), `crs-dataset-probe-${Date.now()}`);
  await mkdir(dir, { recursive: true });
  let hits = 0;
  const scanned = Math.min(limit, plan.positives.length);
  for (const sample of plan.positives.slice(0, scanned)) {
    const raw = JSON.parse(
      readFileSync(join("datasets/self-built/samples", `${sample.sampleId}.json`), "utf8"),
    ) as { after: string };
    const file = join(dir, `${sample.sampleId}.ts`);
    await writeFile(file, raw.after, "utf8");
    const result = await execa(
      "semgrep",
      [
        "--config",
        resolve("research/semgrep-bench/snapshot/ts_all.yaml"),
        "--json",
        "--metrics",
        "off",
        "--disable-version-check",
        file,
      ],
      { env: { ...process.env, PATH: toolPath() }, reject: false, timeout: 60_000 },
    );
    try {
      const parsed = JSON.parse(`${result.stdout}`) as { results?: unknown[] };
      if ((parsed.results ?? []).length > 0) hits += 1;
    } catch {
      // An unparseable envelope already fails the semgrep check above.
    }
  }
  return { hits, scanned };
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
    env: { ...process.env, PATH: toolPath() },
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
        findings: source.findings.map((finding) => ({
          file: finding.file,
          cwe: finding.cwe,
          evidence: finding.evidence,
        })),
      })),
      tokens: row.tokens,
      latency_ms: row.latency_ms,
      change_event: { sessionId: row.change_event.sessionId, ts: row.change_event.ts, phase: row.change_event.phase },
    } as AcceptanceRowLike);
  }
  return out;
}

export async function collect(plan: DrillPlan, outDir: string): Promise<void> {
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
): Promise<{ pass: number; lines: Array<{ name: string; pass: boolean; detail: string }> }> {
  const rows: AcceptanceRowLike[] = [];
  for (const file of await collectJsonl(outDir)) {
    for (const line of (await readFile(file, "utf8")).split("\n")) {
      if (line.trim().length === 0) continue;
      rows.push(JSON.parse(line) as AcceptanceRowLike);
    }
  }
  const gaps = existsSync(gapsPath) ? JSON.parse(await readFile(gapsPath, "utf8")) : null;
  const report = evaluateAcceptance(rows, await loadTruth(datasetDir), gaps);
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

async function main(): Promise<void> {
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const outDir = resolve(arg("--out", "runs/live"));
  const baseConfig = resolve(arg("--config", "configs/b4.json"));
  const profile = arg("--profile", "crs-live");
  const stage = arg("--stage", "all");
  const acceptanceOut = resolve(arg("--acceptance-out", "artifacts/acceptance"));
  const plan = planDrill(datasetDir);

  if (stage === "check") {
    const result = await preflight(profile);
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
            `status=${row.review_status} sources=${row.sources.map((s) => `${s.source}:${s.status}:${s.findings.length}`).join(",")}\n`,
        );
      }
    }
    return;
  }
  if (stage === "prepare" || stage === "all") {
    if (!process.argv.includes("--allow-degraded")) {
      const ready = await preflight(profile);
      if (!ready.ok) {
        process.stdout.write(
          `${ready.checks.map((check) => `${check.ok ? "OK  " : "FAIL"} ${check.name} :: ${check.detail}`).join("\n")}\n`,
        );
        throw new Error("preflight failed; re-run with --allow-degraded for a wiring-only drill");
      }
    }
    await stageDrill({ datasetDir, outDir, baseConfig, profile, plan });
    process.stdout.write(`staged ${allSamples(plan).length} files per baseline in ${outDir}\n`);
  }
  if (stage === "run" || stage === "all") {
    if (!process.env["DEEPSEEK_API_KEY"]) {
      throw new Error("DEEPSEEK_API_KEY is required to run live agent sessions");
    }
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
    await collect(plan, outDir);
  }
  if (stage === "evaluate" || stage === "all") {
    const result = await evaluate(outDir, datasetDir, resolve(arg("--gaps", "artifacts/block-gaps.json")), acceptanceOut);
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
