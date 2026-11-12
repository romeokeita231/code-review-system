import type { MergedFinding } from "../contracts/index.js";

export function resolveConflicts(findings: MergedFinding[]): MergedFinding[] {
  return findings.map((finding) => {
    if (finding.sources.length < 2) return finding;

    const verifiable = finding.rawIds.length > 0 && Boolean(finding.evidence);
    if (verifiable) {
      return { ...finding, conflictResolution: "evidence_preferred" };
    }

    if (!finding.cweComparable) {
      return {
        ...finding,
        conflictResolution: "downgraded",
        blockable: false,
        confidence: Math.min(finding.confidence, 0.5),
      };
    }

    return { ...finding, conflictResolution: "vote" };
  });
}
