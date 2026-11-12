import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { Finding, SourceResult } from "../src/contracts/index.js";
import { stableStringify } from "../src/config/index.js";
import { loadDataset, type DatasetSample } from "../src/l5/index.js";

function findingsFor(sample: DatasetSample, source: "semgrep" | "aor"): Finding[] {
  if (sample.labels.length === 0) return [];
  return sample.labels.map((label, index) => {
    const widen = source === "aor" ? 1 : 0;
    return {
      file: label.path,
      startLine: Math.max(1, label.startLine - widen),
      endLine: label.endLine + widen,
      severity: 3,
      confidence: source === "semgrep" ? 0.99 : 0.97,
      source,
      cwe: label.cwe,
      evidence: `recorded ${source} hit #${index + 1}`,
      rawId: `${source}-${sample.sample_id}-${index}`,
    };
  });
}

function result(source: "semgrep" | "aor", sample: DatasetSample): SourceResult {
  return {
    source,
    status: "ok",
    findings: findingsFor(sample, source),
    coverage: { filesCovered: 1, filesUnknown: 0 },
    tokens: source === "aor" ? 1200 : null,
    latencyMs: source === "semgrep" ? 40 : 900,
  };
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const index = args.indexOf("--out");
  const outDir = resolve(index >= 0 && args[index + 1] ? args[index + 1]! : "tests/fixtures/replay");
  const datasetDir = resolve("datasets/self-built");
  const dataset = await loadDataset(datasetDir);

  for (const sample of dataset.samples) {
    const dir = join(outDir, sample.sample_id);
    await mkdir(dir, { recursive: true });
    await writeFile(join(dir, "semgrep.json"), `${stableStringify(result("semgrep", sample))}\n`, "utf8");
    await writeFile(join(dir, "aor.json"), `${stableStringify(result("aor", sample))}\n`, "utf8");
    const registry: SourceResult = {
      source: "registry",
      status: "ok",
      findings: [],
      coverage: { filesCovered: 1, filesUnknown: 0 },
      tokens: null,
      latencyMs: 5,
    };
    await writeFile(join(dir, "registry.json"), `${stableStringify(registry)}\n`, "utf8");
  }

  process.stdout.write(`recorded ${dataset.samples.length} samples into ${outDir}\n`);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
