export function arg(
  name: string,
  fallback: string,
  argv: readonly string[] = process.argv.slice(2),
): string {
  const index = argv.indexOf(name);
  return index >= 0 && argv[index + 1] ? argv[index + 1]! : fallback;
}

export const CWES = ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-22", "CWE-502", "CWE-798"] as const;
export type Cwe = (typeof CWES)[number];
export type Risk = "low" | "medium" | "high";

export const BASE_RISK: Record<Cwe, Risk> = {
  "CWE-78": "high",
  "CWE-79": "medium",
  "CWE-89": "high",
  "CWE-94": "high",
  "CWE-22": "medium",
  "CWE-502": "high",
  "CWE-798": "low",
};

export const bump = (risk: Risk): Risk => (risk === "low" ? "medium" : "high");

export const riskOf = (cwe: Cwe, changedLines: number): Risk =>
  changedLines >= 10 ? bump(BASE_RISK[cwe]) : BASE_RISK[cwe];

export function diffCount(a: string[], b: string[]): number {
  const n = a.length;
  const m = b.length;
  let previous = new Array<number>(n + 1).fill(0);
  for (let i = 1; i <= m; i += 1) {
    const current = new Array<number>(n + 1).fill(0);
    for (let j = 1; j <= n; j += 1) {
      current[j] =
        a[j - 1] === b[i - 1]
          ? previous[j - 1]! + 1
          : Math.max(previous[j]!, current[j - 1]!);
    }
    previous = current;
  }
  return n + m - 2 * previous[n]!;
}
