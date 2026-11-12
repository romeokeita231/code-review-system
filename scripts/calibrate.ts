import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { calibrationCategories, cweCategory, type CalibrationArtifact, type SourceResult } from "../src/contracts/index.js";
import { assertCalibrationMatches, loadConfig, sha256, stableStringify } from "../src/config/index.js";
import { fitArtifactThresholds, fitCalibration, applyCalibration, fuse } from "../src/l4/index.js";
import { loadDataset, loadRecorded } from "../src/l5/index.js";
import { cweKey, declaredCoverage, loadRulesTable, semgrepLanguage } from "./coverage.js";
import { arg } from "./shared.js";

const DEFAULT_RULES_TABLE = "research/semgrep-bench/snapshot/rules_table.json";

interface Span {
  startLine: number;
  endLine: number;
  cwe: string | null;
}

function overlaps(a: Span, b: Span): boolean {
  return a.startLine <= b.endLine && b.startLine <= a.endLine;
}

function labelOf(
  labels: Span[],
  finding: { startLine: number; endLine: number; cwe: string | null },
): 0 | 1 {
  return labels.some(
    (gold) =>
      overlaps(finding, gold) &&
      (finding.cwe === null || gold.cwe === null || finding.cwe === gold.cwe),
  )
    ? 1
    : 0;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const recordedDir = resolve(arg("--recorded", "tests/fixtures/replay"));
  const outPath = resolve(arg("--out", "artifacts/calibration.json"));
  const configPath = resolve(arg("--config", "configs/b4.json"));
  const rulesTablePath = resolve(arg("--rules-table", DEFAULT_RULES_TABLE));

  const config = await loadConfig(configPath);
  const dataset = await loadDataset(datasetDir);
  const recorded = await loadRecorded(recordedDir);

  // #7 D2: the category set is derived, never hand-written. The ruleset side is
  // "every CWE the frozen rules table declares for a language this config
  // actually scans"; the dataset side is the `sample_cwe` values on the rows.
  const rulesTableText = await readFile(rulesTablePath, "utf8");
  const rulesetFingerprint = sha256(rulesTableText);
  const rulesTable = loadRulesTable(rulesTablePath);
  const scannedLanguages = [
    ...new Set(config.sources.semgrep.subsets.flatMap((subset) => subset.langs)),
  ];
  const declaredCwes = scannedLanguages.flatMap((language) => [
    ...declaredCoverage(rulesTable, language).perCwe.keys(),
  ]);
  const datasetVersion = dataset.manifest.version;
  const categories = calibrationCategories(
    dataset.samples.map((sample) => sample.cwe),
    declaredCwes,
  );

  const synthetic = Object.values(recorded).some((results) =>
    results.some((result) => result.synthetic === true),
  );
  if (synthetic && !args.includes("--allow-synthetic")) {
    throw new Error("recorded sources are synthetic; rerun with --allow-synthetic to fit on them");
  }

  const fitSamples = dataset.samples.filter((sample) => sample.split === "fit");
  const fitRoot = sha256(
    fitSamples
      .map((sample) => {
        const entry = dataset.manifest.samples.find((item) => item.sample_id === sample.sample_id)!;
        return `${sample.sample_id}:${entry.content_sha256}`;
      })
      .sort()
      .join("\n"),
  );

  const calibrationSamples = [] as Array<{
    source: SourceResult["source"];
    category: string;
    raw: number;
    label: 0 | 1;
  }>;
  const scored = [] as Array<{ source: SourceResult["source"]; score: number; label: 0 | 1; category: string }>;

  for (const sample of fitSamples) {
    const results = recorded[sample.sample_id] ?? [];
    for (const result of results) {
      if (result.status !== "ok") continue;
      for (const finding of result.findings) {
        const label = labelOf(sample.labels, {
          startLine: finding.startLine,
          endLine: finding.endLine,
          cwe: finding.cwe ?? null,
        });
        const category = finding.cwe ?? "unknown";
        calibrationSamples.push({ source: result.source, category, raw: finding.confidence, label });
        scored.push({ source: result.source, score: finding.confidence, label, category });
      }
    }
  }

  // Anything the derived category set does not cover is dropped *and reported*:
  // the recorded fixtures still carry CWE-502 findings from the drifted dataset,
  // and a 502 grid surviving in the artifact is exactly the silent mis-fit #7
  // D2 is about. `unknown` (null CWE) is a source-level bucket, not a class.
  const allowedCategories = new Set([...categories, "unknown"]);
  const droppedCategories = new Map<string, number>();
  const keep = (category: string): boolean => {
    // Findings spell classes the same way `calibrationCategories` does, but
    // normalise anyway: a stray `CWE-022` must not fall through as "unfitted".
    if (allowedCategories.has(cweCategory(category) ?? category)) return true;
    droppedCategories.set(category, (droppedCategories.get(category) ?? 0) + 1);
    return false;
  };
  const keptSamples = calibrationSamples.filter((item) => keep(item.category));
  const keptScored = scored.filter((item) => keep(item.category));

  const artifact = fitCalibration(
    keptSamples,
    {
      pPrior: config.prior.pPrior,
      shrinkageN0: 10,
      pMax: 0.95,
      datasetVersion,
      rulesetFingerprint,
      categories,
    },
    fitRoot,
  );

  const calibrated = keptScored.map((item) => ({
    source: item.source,
    score: applyCalibration(
      { source: item.source, cwe: item.category === "unknown" ? null : item.category, confidence: item.score },
      artifact,
      config.prior.pPrior,
    ),
    label: item.label,
    category: item.category,
  }));

  const blockSamples = calibrated
    .filter((item) => item.source === "semgrep")
    .map(({ score, label }) => ({ score, label }));

  const postSamples: Array<{ score: number; label: 0 | 1; category: string }> = [];
  for (const sample of fitSamples) {
    const results = recorded[sample.sample_id] ?? [];
    if (results.length === 0) continue;
    for (const finding of fuse({ sources: results, config, artifact }).findings) {
      const category = finding.cwe ?? "unknown";
      if (!keep(category)) continue;
      postSamples.push({
        score: finding.confidence,
        label: labelOf(sample.labels, {
          startLine: finding.startLine,
          endLine: finding.endLine,
          cwe: finding.cwe ?? null,
        }),
        category,
      });
    }
  }
  const warnSamples = postSamples.map(({ score, label }) => ({ score, label }));

  const blockByCategory = new Map<string, Array<{ score: number; label: 0 | 1 }>>();
  for (const item of calibrated) {
    if (item.source !== "semgrep") continue;
    const bucket = blockByCategory.get(item.category) ?? [];
    bucket.push({ score: item.score, label: item.label });
    blockByCategory.set(item.category, bucket);
  }
  const warnByCategory = new Map<string, Array<{ score: number; label: 0 | 1 }>>();
  for (const item of postSamples) {
    const bucket = warnByCategory.get(item.category) ?? [];
    bucket.push({ score: item.score, label: item.label });
    warnByCategory.set(item.category, bucket);
  }

  const byCategory = new Map<string, { block: Array<{ score: number; label: 0 | 1 }>; warn: Array<{ score: number; label: 0 | 1 }> }>();
  for (const category of new Set([...blockByCategory.keys(), ...warnByCategory.keys()])) {
    byCategory.set(category, {
      block: blockByCategory.get(category) ?? [],
      warn: warnByCategory.get(category) ?? [],
    });
  }

  // Rules per class for the audit record, counted for the languages the fit
  // rows are written in: those are the subsets a scan of them would load, so
  // the number describes the ruleset the fit actually exercised.
  const fitLanguages = new Set(fitSamples.map((sample) => semgrepLanguage(sample.language)));
  const auditLanguages = scannedLanguages.filter((language) => fitLanguages.has(language));
  const declaredRules = new Map<string, number>();
  for (const language of auditLanguages.length > 0 ? auditLanguages : scannedLanguages) {
    for (const [key, ids] of declaredCoverage(rulesTable, language).perCwe) {
      declaredRules.set(key, Math.max(declaredRules.get(key) ?? 0, ids.length));
    }
  }

  const fitted: CalibrationArtifact = {
    ...fitArtifactThresholds(artifact, blockSamples, warnSamples, byCategory, {
      // Design choice, not shortage: negatives are held out in eval so the
      // threshold cannot be tuned against them, which leaves PAVA with one
      // class and makes every score look perfect.
      fit_negatives: fitSamples.filter((sample) => sample.labels.length === 0).length,
      class_declarations: Math.max(0, ...[...blockByCategory.values()].map((samples) => samples.length)),
      class_rules: Math.max(
        0,
        ...[...blockByCategory.keys()].map((category) => declaredRules.get(cweKey(category) ?? category) ?? 0),
      ),
      n_fit: keptScored.length,
    }),
    synthetic,
  };

  // Self-check before writing: the artifact we are about to persist must match
  // the dataset and ruleset it was fitted on, or the next load fails anyway.
  assertCalibrationMatches(fitted, { datasetVersion, rulesetFingerprint, categories });

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${stableStringify(fitted)}\n`, "utf8");
  process.stdout.write(
    `${JSON.stringify({
      out: outPath,
      fitRoot,
      dataset_version: datasetVersion,
      ruleset_fingerprint: rulesetFingerprint,
      categories,
      categories_dropped: Object.fromEntries([...droppedCategories].sort()),
      samples: calibrationSamples.length,
      samples_fitted: keptSamples.length,
      grids: fitted.grids.length,
      thresholds: fitted.thresholds,
    })}\n`,
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
