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
    }
  }
  return best;
}

export interface CategoryThresholdSamples {
  block: ThresholdSample[];
  warn: ThresholdSample[];
}

/**
 * Why a fit produced no operating point. Every cause is recorded on its own:
 * the first is a design choice, the other three are corpus size, and a reader
 * deciding whether to fix the fit needs to know which is which.
 */
export interface ThresholdCauses {
  fit_negatives: number;
  class_declarations: number;
  class_rules: number;
  n_fit: number;
}

export function fitArtifactThresholds(
  artifact: CalibrationArtifact,
  blockSamples: ThresholdSample[],
  warnSamples: ThresholdSample[],
  byCategory: Map<string, CategoryThresholdSamples>,
  causes: ThresholdCauses,
): CalibrationArtifact {
  const block = fitThreshold(blockSamples, 0.9, 10);
  const warn = fitThreshold(warnSamples, 0.7, 10);
  const skipped: { scope: string; reason: string }[] = [];
  if (block.value === null) {
    skipped.push({ scope: "global.block", reason: block.reason ?? "unfitted" });
  }
  if (warn.value === null) {
    skipped.push({ scope: "global.warn", reason: warn.reason ?? "unfitted" });
  }

  const perCategory: Record<string, { block: number | null; warn: number | null }> = {};
  for (const [category, samples] of byCategory) {
    if (samples.block.length < 30 || samples.warn.length < 30) {
      skipped.push({ scope: `category.${category}`, reason: "class_declarations_below_30" });
      continue;
    }
    const catBlock = fitThreshold(samples.block, 0.9, 10);
    const catWarn = fitThreshold(samples.warn, 0.7, 10);
    perCategory[category] = { block: catBlock.value, warn: catWarn.value };
  }

  return {
    ...artifact,
    thresholds: {
      global: { block: block.value, warn: warn.value },
      perCategory,
      skipped,
      status: block.value === null && warn.value === null ? "unfittable" : "fitted",
      causes,
    },
  };
}
