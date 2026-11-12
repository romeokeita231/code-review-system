import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { CalibrationArtifact, SourceResult } from "../src/contracts/index.js";
import { loadConfig, sha256, stableStringify } from "../src/config/index.js";
import { fitArtifactThresholds, fitCalibration, applyCalibration, fuse } from "../src/l4/index.js";
import { loadDataset, loadRecorded } from "../src/l5/index.js";
import { arg } from "./shared.js";

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

  const config = await loadConfig(configPath);
  const dataset = await loadDataset(datasetDir);
  const recorded = await loadRecorded(recordedDir);

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

  const artifact = fitCalibration(
    calibrationSamples,
    { pPrior: config.prior.pPrior, shrinkageN0: 10, pMax: 0.95 },
    fitRoot,
  );

  const calibrated = scored.map((item) => ({
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
      postSamples.push({
        score: finding.confidence,
        label: labelOf(sample.labels, {
          startLine: finding.startLine,
          endLine: finding.endLine,
          cwe: finding.cwe ?? null,
        }),
        category: finding.cwe ?? "unknown",
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

  const fitted: CalibrationArtifact = {
    ...fitArtifactThresholds(artifact, blockSamples, warnSamples, byCategory),
    synthetic,
  };

  await mkdir(dirname(outPath), { recursive: true });
  await writeFile(outPath, `${stableStringify(fitted)}\n`, "utf8");
  process.stdout.write(
    `${JSON.stringify({
      out: outPath,
      fitRoot,
      samples: calibrationSamples.length,
      grids: fitted.grids.length,
      thresholds: fitted.thresholds,
    })}\n`,
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
