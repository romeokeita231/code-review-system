import { describe, expect, it } from "vitest";
import type { MergedFinding } from "../../src/contracts/index.js";
import { DEFAULT_LIMITS, formatMessage, groupsFromFindings, shortenPath } from "../../src/l2/index.js";

const merged = (over: Partial<MergedFinding> = {}): MergedFinding => ({
  file: "src/app.py",
  startLine: 10,
  endLine: 10,
  severity: 3,
  confidence: 0.95,
  source: "semgrep",
  cwe: "CWE-78",
  evidence: "os.system(cmd)",
  rawId: "command-injection-os-system\u0000src/app.py\u000010\u000010",
  sources: ["semgrep"],
  rawIds: ["command-injection-os-system\u0000src/app.py\u000010\u000010"],
  cweComparable: true,
  conflictResolution: "none",
  blockable: true,
  ...over,
});

describe("block template", () => {
  it("collapses the same file and rule into one group", () => {
    const groups = groupsFromFindings([
      merged({ startLine: 10 }),
      merged({ startLine: 12 }),
      merged({ startLine: 11 }),
    ]);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.lines).toEqual([10, 12, 11]);
  });

  it("caps the message at 3 groups and 400 characters", () => {
    const findings = Array.from({ length: 6 }, (_, index) =>
      merged({
        file: `src/module-${index}/very/long/path/that/keeps/going/file_${index}.py`,
        startLine: 10 + index,
        rawId: `rule-${index}\u0000src/file_${index}.py\u0000${10 + index}\u0000${10 + index}`,
      }),
    );
    const text = formatMessage("[CRS-BLOCK]", findings);
    expect(text.split("\n").length).toBeLessThanOrEqual(DEFAULT_LIMITS.maxGroups);
    expect(text.length).toBeLessThanOrEqual(DEFAULT_LIMITS.maxChars);
    for (const line of text.split("\n")) {
      expect(line.length).toBeLessThanOrEqual(DEFAULT_LIMITS.perGroupChars);
    }
  });

  it("orders groups by severity, then file, then first line", () => {
    const text = formatMessage("[CRS-BLOCK]", [
      merged({ file: "b.py", severity: 2, rawId: "r2" }),
      merged({ file: "a.py", severity: 3, rawId: "r1" }),
      merged({ file: "a.py", severity: 3, startLine: 2, rawId: "r0" }),
    ]);
    const lines = text.split("\n");
    expect(lines[0]).toContain("a.py:2");
    expect(lines[1]).toContain("a.py:10");
    expect(lines[2]).toContain("b.py:10");
  });

  it("shortens long paths to the last two segments", () => {
    const long = "src/aaaaaaaaaaaaaaaaaaaa/bbbbbbbbbbbbbbbbbbbb/cccccccccccccccccccc/dddddddddddd.ts";
    expect(shortenPath(long)).toBe("…/cccccccccccccccccccc/dddddddddddd.ts");
  });

  it("keeps scores, confidence, timestamps and code out of the text", () => {
    const text = formatMessage("[CRS-BLOCK]", [merged()]);
    expect(text).not.toMatch(/0\.95/);
    expect(text).not.toContain("os.system");
    expect(text).not.toMatch(/\d{4}-\d{2}-\d{2}/);
  });
});
