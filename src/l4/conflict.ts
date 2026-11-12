import type { MergedFinding } from "../contracts/index.js";

function downgrade(finding: MergedFinding): MergedFinding {
  return {
    ...finding,
    conflictResolution: "downgraded",
    blockable: false,
    confidence: Math.min(finding.confidence, 0.5),
  };
}

export function resolveConflicts(findings: MergedFinding[]): MergedFinding[] {
  return findings.map((finding) => {
    if (finding.sources.length < 2) return finding;

    const withEvidence = new Set(finding.evidenceSources);
    const allVerifiable = finding.sources.every((source) => withEvidence.has(source));
    const anyVerifiable = withEvidence.size > 0;

    if (!finding.cweComparable) return downgrade(finding);
    if (allVerifiable) return { ...finding, conflictResolution: "evidence_preferred" };
    if (anyVerifiable) return { ...finding, conflictResolution: "vote" };
    return downgrade(finding);
  });
}
