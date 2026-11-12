import { describe, expect, it } from "vitest";
import type { MergedFinding } from "../../src/contracts/index.js";
import { intersectionSize, lineUnionSize, mergedIdOf, pair } from "../../src/l5/index.js";

function merged(
  file: string,
  startLine: number,
  endLine: number,
  cwe: string | null = null,
): MergedFinding {
  return {
    file,
    startLine,
    endLine,
    symbol: null,
    severity: 3,
    confidence: 0.5,
    source: "semgrep",
    cwe,
    evidence: null,
    rawId: `${file}:${startLine}:${endLine}:${cwe ?? "-"}`,
    sources: ["semgrep"],
    rawIds: [`${file}:${startLine}:${endLine}:${cwe ?? "-"}`],
    cweComparable: true,
    conflictResolution: "none",
    blockable: true,
  };
}

const gt = (id: string, startLine: number, endLine: number, path = "a.py") => ({
  id,
  path,
  startLine,
  endLine,
  cwe: null,
});

describe("interval helpers", () => {
  it("unions overlapping intervals once", () => {
    expect(lineUnionSize([{ startLine: 1, endLine: 10 }, { startLine: 5, endLine: 15 }])).toBe(15);
    expect(intersectionSize([{ startLine: 1, endLine: 10 }], [{ startLine: 5, endLine: 15 }])).toBe(6);
  });
});

describe("pair", () => {
  it("is independent of input ordering", () => {
    const gts = [gt("g1", 1, 10), gt("g2", 3, 12)];
    const findings = [merged("a.py", 2, 11), merged("a.py", 8, 20)];
    const forward = pair("run", gts, findings);
    const backward = pair("run", [...gts].reverse(), [...findings].reverse());
    expect(backward).toEqual(forward);
    expect(forward).toHaveLength(2);
  });

  it("maximises pair count before overlap", () => {
    const rows = pair(
      "run",
      [gt("g1", 1, 10), gt("g2", 1, 1)],
      [merged("a.py", 1, 10), merged("a.py", 2, 11)],
    );
    expect(rows.every((row) => row.merged_id !== null)).toBe(true);
    expect(rows.find((row) => row.gt_id === "g1")!.merged_id).toBe(
      mergedIdOf(merged("a.py", 2, 11)),
    );
    expect(rows.find((row) => row.gt_id === "g2")!.merged_id).toBe(
      mergedIdOf(merged("a.py", 1, 10)),
    );
  });

  it("maximises total overlap second", () => {
    const rows = pair(
      "run",
      [gt("g1", 1, 10), gt("g2", 1, 5)],
      [merged("a.py", 1, 10), merged("a.py", 1, 4)],
    );
    const g1 = rows.find((row) => row.gt_id === "g1")!;
    const g2 = rows.find((row) => row.gt_id === "g2")!;
    expect(g1.merged_id).toBe(mergedIdOf(merged("a.py", 1, 10)));
    expect(g1.overlap).toBe(10);
    expect(g2.overlap).toBe(4);
  });

  it("minimises total union third when overlap ties", () => {
    const rows = pair("run", [gt("g1", 1, 10)], [
      merged("a.py", 1, 20),
      merged("a.py", 1, 10),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.overlap).toBe(10);
    expect(rows[0]!.union).toBe(10);
    expect(rows[0]!.merged_id).toBe(mergedIdOf(merged("a.py", 1, 10)));
  });

  it("breaks remaining ties by canonical order deterministically", () => {
    const rows = pair(
      "run",
      [gt("gt-b", 1, 10), gt("gt-a", 1, 10)],
      [merged("a.py", 1, 10, "CWE-89"), merged("a.py", 1, 10, "CWE-79")],
    );
    expect(rows.map((row) => row.gt_id)).toEqual(["gt-a", "gt-b"]);
    expect(rows[0]!.merged_id).toBe(mergedIdOf(merged("a.py", 1, 10, "CWE-79")));
    expect(rows[1]!.merged_id).toBe(mergedIdOf(merged("a.py", 1, 10, "CWE-89")));
    expect(pair("run", [gt("gt-a", 1, 10), gt("gt-b", 1, 10)], [
      merged("a.py", 1, 10, "CWE-79"),
      merged("a.py", 1, 10, "CWE-89"),
    ])).toEqual(rows);
  });

  it("is one-to-one and leaves unpaired rows null", () => {
    const rows = pair(
      "run",
      [gt("g1", 1, 10), gt("g2", 1, 10), gt("g3", 40, 50)],
      [merged("a.py", 2, 9)],
    );
    expect(rows.filter((row) => row.merged_id !== null)).toHaveLength(1);
    expect(rows.find((row) => row.gt_id === "g3")).toEqual({
      run_id: "run",
      gt_id: "g3",
      merged_id: null,
      overlap: 0,
      union: 0,
    });
  });

  it("never pairs findings from different paths", () => {
    const rows = pair("run", [gt("g1", 1, 10, "a.py")], [merged("b.py", 1, 10)]);
    expect(rows[0]!.merged_id).toBeNull();
  });
});
