import type { DispositionMechanism, Finding, MergedFinding } from "../contracts/index.js";

export interface TemplateLimits {
  maxGroups: number;
  maxChars: number;
  perGroupChars: number;
  fixClauseChars: number;
  /** Width of the quoted evidence line shown when no class-specific fix exists. */
  evidenceChars: number;
  maxLines: number;
  maxPathChars: number;
}

export const DEFAULT_LIMITS: TemplateLimits = {
  maxGroups: 3,
  // A warning without a class used to be a bare "review the flagged construct":
  // three such lines fit in 400 chars, but adding the evidence line per group
  // needed more room, so the cap and the per-group width were raised together.
  maxChars: 600,
  perGroupChars: 220,
  fixClauseChars: 40,
  evidenceChars: 80,
  maxLines: 3,
  maxPathChars: 60,
};

export interface TemplateGroup {
  file: string;
  ruleId: string;
  startLine: number;
  severity: number;
  cwe: string | null;
  lines: number[];
  fixClause: string;
  /** The flagged source line; the only "what" available when no class is known. */
  evidence: string | null;
  /** Which sources produced this finding; more than one means agreement. */
  sources: string[];
  /** The source whose severity the group carries. */
  severitySource: string;
}

export function groupKey(key: { file: string; ruleId: string }): string {
  return `${key.file}\u0000${key.ruleId}`;
}

export function shortenPath(path: string, maxChars = DEFAULT_LIMITS.maxPathChars): string {
  const posix = path.replace(/\\/g, "/");
  if (posix.length <= maxChars) return posix;
  const segments = posix.split("/");
  const tail = segments.slice(-2).join("/");
  return `…/${tail}`;
}

function clip(text: string, max: number): string {
  if (text.length <= max) return text;
  if (max <= 1) return text.slice(0, max);
  return `${text.slice(0, max - 1)}…`;
}

function sortGroups(groups: TemplateGroup[]): TemplateGroup[] {
  return [...groups].sort((a, b) => {
    if (a.severity !== b.severity) return b.severity - a.severity;
    if (a.file !== b.file) return a.file < b.file ? -1 : 1;
    return a.startLine - b.startLine;
  });
}

function lineList(lines: number[], maxLines: number): string {
  const unique = [...new Set(lines)].sort((a, b) => a - b);
  const shown = unique.slice(0, maxLines).join(",");
  const rest = unique.length - maxLines;
  return rest > 0 ? `${shown} +${rest}` : shown;
}

export function groupsFromFindings(findings: MergedFinding[]): TemplateGroup[] {
  const map = new Map<string, TemplateGroup>();
  for (const finding of findings) {
    const ruleId = finding.rawId.split("\u0000")[0] ?? finding.rawId;
    const key = groupKey({ file: finding.file, ruleId });
    const existing = map.get(key);
    if (existing) {
      existing.lines.push(finding.startLine);
      // Keep the evidence of the most severe finding in the group: the line a
      // reader is pointed at should be the one that scored highest.
      if (finding.severity > existing.severity && finding.evidence) {
        existing.evidence = finding.evidence;
      }
      continue;
    }
    map.set(key, {
      file: finding.file,
      ruleId,
      startLine: finding.startLine,
      severity: finding.severity,
      cwe: finding.cwe ?? null,
      lines: [finding.startLine],
      fixClause: fixClauseFor(finding),
      evidence: finding.evidence ?? null,
      sources: [...finding.sources].sort(),
      severitySource: finding.severitySource ?? finding.source,
    });
  }
  return sortGroups([...map.values()]);
}

function fixClauseFor(finding: Finding | MergedFinding): string {
  const cwe = finding.cwe ?? "";
  switch (cwe) {
    case "CWE-78":
      return "avoid shell interpolation";
    case "CWE-79":
      return "escape or sanitize output";
    case "CWE-89":
      return "use parameterized queries";
    case "CWE-94":
      return "avoid dynamic code execution";
    case "CWE-22":
      return "validate and confine paths";
    case "CWE-502":
      return "avoid unsafe deserialization";
    case "CWE-798":
      return "move secret out of source";
    default:
      return "review the flagged construct";
  }
}

function provenanceTag(group: TemplateGroup): string {
  const via = `${group.sources.join("+")}${group.sources.length > 1 ? "/agree" : ""}`;
  // `severity_source` alone said who scored it, not how high; a reader cannot
  // rank `sev=aor` against `sev=semgrep` without the number.
  return `via=${via}/sev=${group.severitySource}/${group.severity}`;
}

/**
 * Without a class there is no class-specific fix, and "review the flagged
 * construct" gives a reader nothing to act on. The flagged source line is the
 * one piece of "what" AOR does provide, so use it there.
 */
function fixOrEvidence(group: TemplateGroup, limits: TemplateLimits): string {
  const evidence = group.evidence?.replace(/\s+/g, " ").trim();
  if (group.cwe !== null || !evidence) return clip(group.fixClause, limits.fixClauseChars);
  return `see: ${clip(evidence, limits.evidenceChars)}`;
}

function buildLine(group: TemplateGroup, limits: TemplateLimits, anchor: string): string {
  const path = shortenPath(group.file, limits.maxPathChars);
  const cwe = group.cwe ? `${group.cwe} ` : "";
  const lines = lineList(group.lines, limits.maxLines);
  const fix = fixOrEvidence(group, limits);
  // Provenance first: `sources`, agreement and `severity_source` must survive
  // clipping, so the tag sits before the path instead of after the fix clause.
  const head = `${anchor} ${provenanceTag(group)} ${path}:${lines} ${cwe}${group.ruleId}`.replace(/\s+/g, " ").trim();
  const withFix = `${head} | ${fix}`;
  return clip(withFix, limits.perGroupChars);
}

export function formatMessage(
  anchor: "[CRS-BLOCK]" | "[CRS-WARN]",
  findings: MergedFinding[],
  limits: TemplateLimits = DEFAULT_LIMITS,
): string {
  const groups = groupsFromFindings(findings).slice(0, limits.maxGroups);
  const lines = groups.map((group) => buildLine(group, limits, anchor));
  let text = lines.join("\n");
  if (text.length > limits.maxChars) {
    text = clip(text, limits.maxChars);
  }
  return text;
}

export function mechanismOf(decision: "deny" | "allow" | "inject_warn" | "none"): DispositionMechanism {
  if (decision === "deny") return "mechanical_block";
  if (decision === "inject_warn") return "instruction_correction";
  return "record";
}
