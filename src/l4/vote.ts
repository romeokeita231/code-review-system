import type { Finding, MergedFinding, RunConfig } from "../contracts/index.js";
import { logit, sigmoid } from "./calibration.js";

export function weightFor(sourceCount: number, config: RunConfig): number {
  return sourceCount >= 2 ? config.weights.dual : config.weights.single;
}

export function fuseLogOdds(probabilities: number[], weight: number, pPrior: number): number {
  const prior = logit(pPrior);
  const evidence = probabilities.reduce((acc, p) => acc + (logit(p) - prior), 0);
  return prior + weight * evidence;
}

export function fuseProbability(probabilities: number[], weight: number, pPrior: number): number {
  if (probabilities.length === 0) return pPrior;
  return sigmoid(fuseLogOdds(probabilities, weight, pPrior));
}

export function probabilityByRawId(findings: Finding[], resolve: (f: Finding) => number): Map<string, number> {
  const map = new Map<string, number>();
  for (const finding of findings) {
    map.set(finding.rawId, resolve(finding));
  }
  return map;
}

export function probabilitiesFor(merged: MergedFinding, rawProbabilities: Map<string, number>): number[] {
  const values = merged.rawIds
    .map((id) => rawProbabilities.get(id))
    .filter((p): p is number => typeof p === "number");
  return values.length > 0 ? values : [merged.confidence];
}

export function vote(
  findings: MergedFinding[],
  rawProbabilities: Map<string, number>,
  config: RunConfig,
): MergedFinding[] {
  return findings.map((finding) => {
    const probs = probabilitiesFor(finding, rawProbabilities);
    const weight = weightFor(finding.sources.length, config);
    const fused = fuseProbability(probs, weight, config.prior.pPrior);
    return { ...finding, confidence: fused };
  });
}
