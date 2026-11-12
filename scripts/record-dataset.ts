/**
 * Record real detector output for one dataset split.
 *
 * The replay layer scores recorded `SourceResult`s; the calibration is fitted
 * on them. Fabricating those rows (`seed-recordings.ts`) is fine for the
 * pipeline's own tests, but a recall number has to come from a real detector
 * run. This script stages each sample's `after` side into a scratch tree and
 * runs the concrete source against it, then writes the result where
 * `loadRecorded` reads it.
 *
 *   --split fit    (default) record the fit split
 *   --split eval   refused without `--allow-eval`: the eval split may only be
 *                  recorded once the calibration is frozen (issue #41 order)
 *   --matrix       print the declared-coverage matrix for the recorded rows
 *   --dry-run      scan and report without writing recordings
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Finding, RunConfig, SourceResult } from "../src/contracts/index.js";
import { loadConfig, stableStringify } from "../src/config/index.js";
import { createSemgrepSource } from "../src/l3/index.js";
import { changeEventOf, loadDataset, type DatasetSample } from "../src/l5/index.js";
import { declaredCoverage, cweKey, loadRulesTable, rulesFor } from "./coverage.js";

const DEFAULT_RULES_TABLE = "research/semgrep-bench/snapshot/rules_table.json";

interface RowReport {
  sample: string;
  cwe: string | null;
  language: string;
  findings: number;
  hit: boolean;
  status: string;
  declaredRules: number;
  latencyMs: number;
}

/**
 * The source resolves its rule files against `root`, and materialises scanned
 * content into its own temp tree from `sourceText`, so the scratch root must be
 * the repository (where `research/semgrep-bench` lives), not a sample directory.
 * Nothing is written: the sample text is passed through `sourceText`.
 */

function overlaps(finding: Finding, sample: DatasetSample): boolean {
  const gold = sample.labels;
  return gold.some(
    (label) =>
      finding.startLine <= label.endLine &&
      label.startLine <= finding.endLine &&
      (finding.cwe === null || label.cwe === null || finding.cwe === label.cwe),
  );
}

async function scan(config: RunConfig, sample: DatasetSample, root: string): Promise<SourceResult> {
  const source = createSemgrepSource(config, { root });
  return source.review({
    event: changeEventOf(sample),
    tier: 1,
    config,
    deadline: Date.now() + config.sources.semgrep.timeoutsMs.callMs * 4,
    sourceText: { [sample.path]: sample.after },
  });
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const datasetDir = resolve("datasets/self-built");
  const recordedDir = resolve("tests/fixtures/replay");
  const configPath = resolve(argv.includes("--config") ? argv[argv.indexOf("--config") + 1]! : "configs/b4.json");
  const rulesTablePath = resolve(
    argv.includes("--rules-table") ? argv[argv.indexOf("--rules-table") + 1]! : DEFAULT_RULES_TABLE,
  );
  const split = argv.includes("--split") ? argv[argv.indexOf("--split") + 1] : "fit";
  const dryRun = argv.includes("--dry-run");
  const matrix = argv.includes("--matrix");

  if (split !== "fit" && split !== "eval") throw new Error(`--split must be fit|eval, got ${String(split)}`);
  if (split === "eval" && !argv.includes("--allow-eval")) {
    throw new Error("refusing to record eval: the calibration must be frozen first (pass --allow-eval to override)");
  }

  const config = await loadConfig(configPath);
  const dataset = await loadDataset(datasetDir);
  const rows = dataset.samples.filter((sample) => sample.split === split);
  if (rows.length === 0) throw new Error(`no ${split} rows in ${datasetDir}`);

  const table = loadRulesTable(rulesTablePath);
  const coverageByLanguage = new Map<string, ReturnType<typeof declaredCoverage>>();
  const coverageFor = (language: string): ReturnType<typeof declaredCoverage> => {
    const cached = coverageByLanguage.get(language);
    if (cached !== undefined) return cached;
    const computed = declaredCoverage(table, language);
    coverageByLanguage.set(language, computed);
    return computed;
  };

  const root = process.cwd();
  const reports: RowReport[] = [];
  {
    for (const sample of rows) {
      const result = await scan(config, sample, root);
      const coverage = coverageFor(sample.language);
      const hit = result.findings.some((finding) => overlaps(finding, sample));
      reports.push({
        sample: sample.sample_id,
        cwe: sample.cwe,
        language: sample.language,
        findings: result.findings.length,
        hit,
        status: result.status,
        declaredRules: rulesFor(coverage, sample.cwe).length,
        latencyMs: result.latencyMs,
      });
      if (!dryRun) {
        const dir = join(recordedDir, sample.sample_id);
        await mkdir(dir, { recursive: true });
        await writeFile(join(dir, "semgrep.json"), `${stableStringify(result)}\n`, "utf8");
      }
      process.stdout.write(
        `${sample.sample_id} ${String(sample.cwe)} ${result.status} findings=${result.findings.length} ` +
          `hit=${hit ? "yes" : "no"} ${Math.round(result.latencyMs)}ms\n`,
      );
    }
  }

  if (matrix) {
    const classes = [...new Set(reports.map((report) => cweKey(report.cwe) ?? "none"))].sort();
    process.stdout.write("\nclass  rows  hit  declared  findings\n");
    for (const key of classes) {
      const inClass = reports.filter((report) => (cweKey(report.cwe) ?? "none") === key);
      const hits = inClass.filter((report) => report.hit).length;
      const findings = inClass.reduce((sum, report) => sum + report.findings, 0);
      const declared = Math.max(...inClass.map((report) => report.declaredRules));
      process.stdout.write(`${key.padEnd(6)} ${String(inClass.length).padEnd(5)} ${String(hits).padEnd(4)} ${String(declared).padEnd(9)} ${findings}\n`);
    }
    const unscanned = reports.filter((report) => report.status !== "ok");
    process.stdout.write(
      `\nrows=${reports.length} hit=${reports.filter((report) => report.hit).length} ` +
        `findings=${reports.reduce((sum, report) => sum + report.findings, 0)} ` +
        `not_ok=${unscanned.length}${unscanned.length > 0 ? `: ${unscanned.map((row) => `${row.sample}=${row.status}`).join(",")}` : ""}\n`,
    );
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
void fileURLToPath;
