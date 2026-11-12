import { describe, expect, it } from "vitest";
import {
  coverageCounts,
  cweKey,
  declaredCoverage,
  loadRulesTable,
  rulesFor,
  semgrepLanguage,
} from "../../scripts/coverage.js";

const table = {
  rules: [
    { id: "a", languages: ["javascript", "typescript"], cwe: ["079"] },
    { id: "b", languages: "typescript", cwe: ["022", "918"] },
    { id: "c", languages: "python", cwe: ["022"] },
    { id: "d", languages: ["javascript"], cwe: ["502"] },
    { id: "e", languages: ["typescript"], cwe: ["CWE-79: Improper Neutralization"] },
  ],
};

describe("cweKey", () => {
  it("normalises the spellings the dataset and the rules table both use", () => {
    expect(cweKey("CWE-22")).toBe("022");
    expect(cweKey("CWE-022")).toBe("022");
    expect(cweKey("079")).toBe("079");
    expect(cweKey("CWE-79: Improper Neutralization of Input")).toBe("079");
    expect(cweKey(null)).toBeNull();
    expect(cweKey("not a cwe")).toBeNull();
  });
});

describe("semgrepLanguage", () => {
  it("maps dataset languages to semgrep target languages", () => {
    expect(semgrepLanguage("ts")).toBe("typescript");
    expect(semgrepLanguage("TSX")).toBe("typescript");
    expect(semgrepLanguage("js")).toBe("javascript");
    expect(semgrepLanguage("python")).toBe("python");
  });
});

describe("declaredCoverage", () => {
  it("counts only rules that declare the target language", () => {
    const coverage = declaredCoverage(table, "ts");
    expect(rulesFor(coverage, "CWE-079")).toEqual(["a", "e"]);
    expect(rulesFor(coverage, "CWE-022")).toEqual(["b"]);
    // Rule "d" is javascript-only, so a .ts file cannot be scanned by it.
    expect(rulesFor(coverage, "CWE-502")).toEqual([]);
  });

  it("counts python rules for python samples", () => {
    expect(rulesFor(declaredCoverage(table, "python"), "CWE-022")).toEqual(["c"]);
  });

  it("exposes plain counts for reports", () => {
    expect(coverageCounts(declaredCoverage(table, "ts"))).toEqual({ "022": 1, "079": 2, "918": 1 });
  });

  it("reads the frozen rules table", () => {
    const loaded = loadRulesTable("research/semgrep-bench/snapshot/rules_table.json");
    expect(loaded.rules.length).toBeGreaterThan(100);
    const coverage = declaredCoverage(loaded, "ts");
    // The seven classes the annotation spec asks for are declared; 502 is not.
    for (const cwe of ["022", "078", "079", "089", "094", "798", "918"]) {
      expect(rulesFor(coverage, `CWE-${cwe}`).length, cwe).toBeGreaterThan(0);
    }
    expect(rulesFor(coverage, "CWE-502")).toEqual([]);
  });
});
