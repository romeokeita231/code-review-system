import type { CalibrationArtifact, CalibrationGrid, Finding, SourceName } from "../contracts/index.js";

export const P_MAX = 0.95;
export const UNKNOWN_CATEGORY = "unknown";

export interface CalibrationSpec {
  pPrior: number;
  shrinkageN0: number;
  pMax: number;
  /** Provenance of the fit; recorded so a stale artifact is detectable (#7 D2). */
  datasetVersion: string;
  rulesetFingerprint: string;
  /** `calibrationCategories(dataset, ruleset)` — never a hand-written list. */
  categories: string[];
}

export interface CalibrationSample {
  source: SourceName;
  category: string;
  raw: number;
  label: 0 | 1;
}

export function categoryOf(finding: Pick<Finding, "cwe">): string {
  return finding.cwe ?? UNKNOWN_CATEGORY;
}

export function logit(p: number): number {
  const clamped = Math.min(Math.max(p, 1e-6), 1 - 1e-6);
  return Math.log(clamped / (1 - clamped));
}

export function sigmoid(x: number): number {
  if (x >= 0) return 1 / (1 + Math.exp(-x));
  const e = Math.exp(x);
  return e / (1 + e);
}

function pava(values: number[], weights: number[]): number[] {
  const blocks: { sum: number; weight: number; count: number }[] = [];
  for (let i = 0; i < values.length; i += 1) {
    blocks.push({ sum: values[i]! * weights[i]!, weight: weights[i]!, count: 1 });
    while (blocks.length > 1) {
      const last = blocks[blocks.length - 1]!;
      const prev = blocks[blocks.length - 2]!;
      const prevMean = prev.sum / prev.weight;
      const lastMean = last.sum / last.weight;
      if (lastMean >= prevMean - 1e-12) break;
      blocks.splice(blocks.length - 2, 2, {
        sum: prev.sum + last.sum,
        weight: prev.weight + last.weight,
        count: prev.count + last.count,
      });
    }
  }
  const out: number[] = [];
  for (const block of blocks) {
    const mean = block.sum / block.weight;
    for (let i = 0; i < block.count; i += 1) out.push(mean);
  }
  return out;
}

export function fitCalibration(
  samples: CalibrationSample[],
  spec: CalibrationSpec,
  fitRoot: string,
): CalibrationArtifact {
  const buckets = new Map<string, Map<number, { hits: number; total: number }>>();
  for (const sample of samples) {
    const key = `${sample.source}\u0000${sample.category}`;
    if (!buckets.has(key)) buckets.set(key, new Map());
    const rawMap = buckets.get(key)!;
    const entry = rawMap.get(sample.raw) ?? { hits: 0, total: 0 };
    entry.total += 1;
    entry.hits += sample.label;
    rawMap.set(sample.raw, entry);
  }

  const grids: CalibrationGrid[] = [];
  for (const [key, rawMap] of [...buckets.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const [source, category] = key.split("\u0000") as [SourceName, string];
    const raws = [...rawMap.keys()].sort((a, b) => a - b);
    const n = raws.reduce((acc, raw) => acc + rawMap.get(raw)!.total, 0);
    const counts = raws.map((raw) => rawMap.get(raw)!.total);
    const shrunk = raws.map((raw) => {
      const entry = rawMap.get(raw)!;
      return (entry.hits + spec.shrinkageN0 * spec.pPrior) / (entry.total + spec.shrinkageN0);
    });
    const monotone = pava(shrunk, counts).map((p) =>
      Math.min(Math.max(p, spec.pPrior), spec.pMax),
    );

    const points: CalibrationGrid["points"] = [];
    for (let i = 0; i < raws.length; i += 1) {
      const p = monotone[i]!;
      const raw = raws[i]!;
      const prev = points[points.length - 1];
      if (prev && Math.abs(prev.p - p) < 1e-12) {
        prev.rawHigh = raw;
      } else {
        points.push({ rawLow: raw, rawHigh: raw, p });
      }
    }
    grids.push({ source, category, n, points });
  }

  return {
    version: `calib-${fitRoot.slice(0, 12)}`,
    dataset_version: spec.datasetVersion,
    ruleset_fingerprint: spec.rulesetFingerprint,
    categories: [...spec.categories].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    pPrior: spec.pPrior,
    shrinkageN0: spec.shrinkageN0,
    pMax: spec.pMax,
    fitRoot,
    grids,
    thresholds: {
      global: { block: null, warn: null },
      perCategory: {},
      skipped: [],
    },
  };
}

export function applyCalibration(
  finding: Pick<Finding, "source" | "cwe" | "confidence">,
  artifact: CalibrationArtifact | null,
  pPrior: number,
): number {
  const prior = artifact?.pPrior ?? pPrior;
  const pMax = artifact?.pMax ?? P_MAX;
  if (!artifact) return Math.min(prior, pMax);
  const category = categoryOf(finding);
  const grid =
    artifact.grids.find((g) => g.source === finding.source && g.category === category) ??
    artifact.grids.find((g) => g.source === finding.source && g.category === UNKNOWN_CATEGORY);
  if (!grid || grid.points.length === 0) return prior;

  const points = grid.points;
  if (finding.confidence <= points[0]!.rawHigh) return Math.min(Math.max(points[0]!.p, prior), pMax);
  for (let i = 1; i < points.length; i += 1) {
    const point = points[i]!;
    if (finding.confidence <= point.rawHigh) {
      return Math.min(Math.max(point.p, prior), pMax);
    }
  }
  return Math.min(Math.max(points[points.length - 1]!.p, prior), pMax);
}
