import type {
  CalibrationArtifact,
  Finding,
  MergedFinding,
  RunConfig,
  SourceResult,
} from "../contracts/index.js";
import { applyCalibration } from "./calibration.js";
import { resolveConflicts } from "./conflict.js";
import { mergeFindings } from "./merge.js";
import { probabilitiesFor, probabilityByRawId, vote, weightFor } from "./vote.js";

export { fitCalibration, applyCalibration, categoryOf, logit, sigmoid } from "./calibration.js";
export { fitThreshold, fitArtifactThresholds } from "./thresholds.js";
export { mergeFindings, intervalsIntersect, categoriesComparable } from "./merge.js";
export { resolveConflicts } from "./conflict.js";
export { fuseProbability, fuseLogOdds, weightFor, vote } from "./vote.js";

export interface FusionInput {
  sources: SourceResult[];
  config: RunConfig;
  artifact: CalibrationArtifact | null;
}

export interface FusionOutput {
  findings: MergedFinding[];
  pFused: number | null;
  degradedOnly: boolean;
}

function asMerged(finding: Finding): MergedFinding {
  return {
    ...finding,
    sources: [finding.source],
    rawIds: [finding.rawId],
    cweComparable: true,
    conflictResolution: "none",
    blockable: true,
  };
}

export function fuse({ sources, config, artifact }: FusionInput): FusionOutput {
  const degradedSources = new Set(
    sources.filter((s) => s.status !== "ok").map((s) => s.source),
  );
  const raw = sources.flatMap((s) => s.findings);

  if (raw.length === 0) {
    return { findings: [], pFused: null, degradedOnly: sources.every((s) => s.status !== "ok") };
  }

  const stages = config.fusionStages;
  let merged: MergedFinding[] = stages.merge ? mergeFindings(raw) : raw.map(asMerged);

  if (stages.conflict && stages.merge) merged = resolveConflicts(merged);

  const resolved = (finding: Finding): number => {
    if (stages.calibrate) return applyCalibration(finding, artifact, config.prior.pPrior);
    return finding.confidence;
  };
  const rawProbabilities = probabilityByRawId(raw, resolved);

  if (stages.vote) {
    merged = vote(merged, rawProbabilities, config);
  } else {
    merged = merged.map((finding) => {
      const probs = probabilitiesFor(finding, rawProbabilities);
      return { ...finding, confidence: Math.max(...probs) };
    });
  }

  merged = merged.map((finding) => {
    const touchesDegraded = finding.sources.some((s) => degradedSources.has(s));
    return touchesDegraded ? { ...finding, blockable: false } : finding;
  });

  const pFused = merged.reduce((max, finding) => Math.max(max, finding.confidence), 0);
  const degradedOnly = merged.every((f) => !f.blockable);

  return { findings: merged, pFused: merged.length > 0 ? pFused : null, degradedOnly };
}

export function singleSourceProbability(finding: Finding, config: RunConfig, artifact: CalibrationArtifact | null): number {
  return applyCalibration(finding, artifact, config.prior.pPrior);
}

export function weightOf(finding: MergedFinding, config: RunConfig): number {
  return weightFor(finding.sources.length, config);
}
