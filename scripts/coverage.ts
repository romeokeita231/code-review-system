import { readFileSync } from "node:fs";

/**
 * Which CWE classes the pinned ruleset *declares* it can match, per language.
 *
 * This exists because `expected_detectable_by` must never select the recall
 * denominator (annotation spec §6: the field is "非真值、不进任何指标"). The
 * subset is decided before unblinding by a mechanical fact instead: does the
 * frozen `rules_table.json` contain at least one rule that declares this CWE
 * for this language? That is a declaration, not an observed hit, so it cannot
 * be contaminated by running Semgrep over the samples.
 */

export interface RuleRecord {
  id: string;
  languages: string | string[];
  cwe: string | string[] | null;
}

export interface RulesTable {
  rules: RuleRecord[];
}

const asArray = <T>(value: T | T[] | null | undefined): T[] => {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? value : [value];
};

/** `CWE-22` / `CWE-022` / `022` / `CWE-79: Improper ...` all normalise to `022`. */
export function cweKey(raw: string | null | undefined): string | null {
  if (raw === null || raw === undefined) return null;
  const text = String(raw).trim();
  const labelled = /CWE-(\d{1,4})/i.exec(text);
  const digits = labelled?.[1] ?? (/^\d{1,4}$/.test(text) ? text : undefined);
  if (digits === undefined) return null;
  return digits.padStart(3, "0");
}

export function languagesOf(rule: RuleRecord): string[] {
  return asArray(rule.languages).map((language) => String(language).toLowerCase());
}

/** The Semgrep target language a dataset language is scanned as. */
export function semgrepLanguage(language: string): string {
  const normalized = language.toLowerCase();
  if (normalized === "ts" || normalized === "tsx" || normalized === "typescript") return "typescript";
  if (normalized === "js" || normalized === "jsx" || normalized === "javascript") return "javascript";
  return normalized;
}

export interface DeclaredCoverage {
  /** Semgrep target language the counts are filtered on. */
  language: string;
  /** CWE key -> ids of rules that declare it for this language. */
  perCwe: Map<string, string[]>;
}

export function declaredCoverage(table: RulesTable, language: string): DeclaredCoverage {
  const target = semgrepLanguage(language);
  const perCwe = new Map<string, string[]>();
  for (const rule of table.rules) {
    if (!languagesOf(rule).includes(target)) continue;
    for (const cwe of asArray(rule.cwe)) {
      const key = cweKey(cwe);
      if (key === null) continue;
      const ids = perCwe.get(key) ?? [];
      if (!ids.includes(rule.id)) ids.push(rule.id);
      perCwe.set(key, ids);
    }
  }
  return { language: target, perCwe };
}

export function rulesFor(coverage: DeclaredCoverage, cwe: string | null): string[] {
  const key = cweKey(cwe);
  if (key === null) return [];
  return coverage.perCwe.get(key) ?? [];
}

/** Plain-object view for JSON plans and reports. */
export function coverageCounts(coverage: DeclaredCoverage): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [key, ids] of [...coverage.perCwe].sort(([a], [b]) => a.localeCompare(b))) {
    out[key] = ids.length;
  }
  return out;
}

/**
 * Synchronous on purpose: the drill plan is a pure function of the dataset and
 * the frozen rules table, so it must not depend on an event loop turn.
 */
export function loadRulesTable(path: string): RulesTable {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as { rules?: unknown };
  const rules = Array.isArray(parsed.rules) ? parsed.rules : [];
  return {
    rules: rules.map((raw) => {
      const record = raw as Partial<RuleRecord>;
      return {
        id: String(record.id ?? ""),
        languages: record.languages ?? [],
        cwe: record.cwe ?? null,
      };
    }),
  };
}
