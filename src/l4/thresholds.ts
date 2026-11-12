import type { CalibrationArtifact } from "../contracts/index.js";

export interface ThresholdSample {
  score: number;
  label: 0 | 1;
}

export interface ThresholdFit {
  value: number | null;
  reason: string | null;
  precision: number | null;
  support: number;
}

export function fitThreshold(
  samples: ThresholdSample[],
  targetPrecision: number,
  minSupport: number,
): ThresholdFit {
  if (samples.length === 0) {
    return { value: null, reason: "no_declarations", precision: null, support: 0 };
  }
  const ordered = [...samples].sort((a, b) => b.score - a.score);
  let hits = 0;
  let support = 0;
  let best: ThresholdFit = { value: null, reason: "insufficient_support", precision: null, support: 0 };

  for (const sample of ordered) {
    support += 1;
    hits += sample.label;
    if (support < minSupport) continue;
    const precision = hits / support;
    if (precision >= targetPrecision) {
      best = { value: sample.score, reason: null, precision, support };
    } else {
      break;
    }
  }
  return best;
}

export function fitArtifactThresholds(
  artifact: CalibrationArtifact,
  global: ThresholdSample[],
  byCategory: Map<string, ThresholdSample[]>,
): CalibrationArtifact {
  const block = fitThreshold(global, 0.9, 10);
  const warn = fitThreshold(global, 0.7, 10);
  const skipped: { scope: string; reason: string }[] = [];
  if (block.value === null) {
    skipped.push({ scope: "global.block", reason: block.reason ?? "unfitted" });
  }
  if (warn.value === null) {
    skipped.push({ scope: "global.warn", reason: warn.reason ?? "unfitted" });
  }

  const perCategory: Record<string, { block: number | null; warn: number | null }> = {};
  for (const [category, samples] of byCategory) {
    if (samples.length < 30) {
      skipped.push({ scope: `category.${category}`, reason: "class_declarations_below_30" });
      continue;
    }
    const catBlock = fitThreshold(samples, 0.9, 10);
    const catWarn = fitThreshold(samples, 0.7, 10);
    perCategory[category] = { block: catBlock.value, warn: catWarn.value };
  }

  return {
    ...artifact,
    thresholds: {
      global: { block: block.value, warn: warn.value },
      perCategory,
      skipped,
    },
  };
}
