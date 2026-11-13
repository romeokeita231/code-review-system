import type { Finding, MergedFinding } from "../contracts/index.js";

export function intervalsIntersect(a: Finding, b: Finding): boolean {
  return a.startLine <= b.endLine && b.startLine <= a.endLine;
}

export function categoriesComparable(a: Finding, b: Finding): boolean {
  if (a.cwe && b.cwe) return a.cwe === b.cwe;
  return true;
}

function joinable(group: Finding[], finding: Finding): boolean {
  if (!group.every((member) => member.file === finding.file)) return false;
  if (!group.some((member) => intervalsIntersect(member, finding))) return false;
  return !group.some((member) => !categoriesComparable(member, finding));
}

function toMerged(group: Finding[]): MergedFinding {
  const sorted = [...group].sort((x, y) => {
    if (y.confidence !== x.confidence) return y.confidence - x.confidence;
    if (x.source !== y.source) return x.source < y.source ? -1 : 1;
    return x.rawId < y.rawId ? -1 : x.rawId > y.rawId ? 1 : 0;
  });
  const head = sorted[0]!;
  const sources = [...new Set(group.map((f) => f.source))].sort();
  const cwes = group.map((f) => f.cwe).filter((c): c is string => Boolean(c));
  const evidences = group.map((f) => f.evidence).filter((e): e is string => Boolean(e));
  const maxSeverity = Math.max(...group.map((f) => f.severity));
  const severitySource = group.find((f) => f.severity === maxSeverity)?.source ?? null;
  return {
    file: head.file,
    startLine: Math.min(...group.map((f) => f.startLine)),
    endLine: Math.max(...group.map((f) => f.endLine)),
    symbol: head.symbol ?? null,
    severity: Math.max(...group.map((f) => f.severity)),
    severitySource,
    confidence: head.confidence,
    source: head.source,
    cwe: cwes.length > 0 && new Set(cwes).size === 1 ? cwes[0]! : (head.cwe ?? null),
    evidence: evidences.length > 0 ? evidences.join(" | ") : null,
    rawId: head.rawId,
    sources,
    rawIds: group.map((f) => f.rawId),
    evidenceSources: [...new Set(group.filter((f) => f.evidence).map((f) => f.source))].sort(),
    certified: group.every((f) => f.certified !== false),
    cweComparable: !(group.some((f) => f.cwe) && group.some((f) => !f.cwe)),
    conflictResolution: "none",
    blockable: true,
  };
}

export function mergeFindings(findings: Finding[]): MergedFinding[] {
  const groups: Finding[][] = [];
  const ordered = [...findings].sort((a, b) => {
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    if (a.startLine !== b.startLine) return a.startLine - b.startLine;
    return a.rawId < b.rawId ? -1 : a.rawId > b.rawId ? 1 : 0;
  });
  for (const finding of ordered) {
    const hit = groups.find((g) => joinable(g, finding));
    if (hit) hit.push(finding);
    else groups.push([finding]);
  }
  return groups.map(toMerged).sort((a, b) => {
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.startLine - b.startLine;
  });
}
