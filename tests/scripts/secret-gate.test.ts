import { describe, expect, it } from "vitest";
import {
  evaluateSecretGate,
  EXEMPT_ZONES,
  isExempt,
  parseProvenance,
  scanFiles,
  scanText,
  type Hit,
} from "../../scripts/secret-gate.js";

/**
 * Sample values are assembled from pieces on purpose: this file is tracked, and
 * the gate scans everything outside its three exempt zones, so a literal key
 * shape here would make the gate fail on its own test.
 */
const join = (...parts: string[]): string => parts.join("");
const SAMPLES = {
  sk: join("sk", "-", "a".repeat(24)),
  AIza: join("AI", "za", "B".repeat(35)),
  ghp: join("gh", "p_", "c".repeat(36)),
  github_pat: join("github", "_pat_", "d".repeat(24)),
  xox: join("xo", "xb-", "e".repeat(12)),
  AKIA: join("AK", "IA", "F".repeat(16)),
  "PRIVATE KEY": join("-----BE", "GIN ", "RSA PRIVATE KEY-----"),
} as const;

const HEADER = "| file | provider | repo | commit | note |";
const SEPARATOR = "| --- | --- | --- | --- | --- |";

const registryRow = (file: string, provider: string, repo = "cline/cline", commit = "190d3bd") =>
  `| ${file} | ${provider} | ${repo} | ${commit} | why the bytes are there |`;

describe("scanText", () => {
  it("counts every provider shape, not just the one the first scan looked for", () => {
    const text = Object.values(SAMPLES).join("\n");
    expect(Object.fromEntries(scanText(text))).toEqual({
      sk: 1,
      AIza: 1,
      ghp: 1,
      github_pat: 1,
      xox: 1,
      AKIA: 1,
      "PRIVATE KEY": 1,
    });
  });

  it("counts occurrences, so three keys on one line are three", () => {
    const text = `${SAMPLES.AIza} ${SAMPLES.AIza} ${SAMPLES.AIza}`;
    expect(scanText(text).get("AIza")).toBe(3);
  });

  it("does not carry a match from one file into the next", () => {
    expect(scanText(SAMPLES.AKIA).get("AKIA")).toBe(1);
    expect(scanText("nothing here").size).toBe(0);
    expect(scanText(SAMPLES.AKIA).get("AKIA")).toBe(1);
  });
});

describe("isExempt", () => {
  it("matches the three zones by prefix, not by substring", () => {
    expect(EXEMPT_ZONES).toEqual(["datasets/", "research/", "artifacts/acceptance/"]);
    expect(isExempt("datasets/aacr/samples/x.json")).toBe(true);
    expect(isExempt("research/semgrep-bench/_raw_core_py.json")).toBe(true);
    expect(isExempt("artifacts/acceptance/rows.jsonl")).toBe(true);
    expect(isExempt("datasets2/x.json")).toBe(false);
    expect(isExempt("src/l2/orchestrator.ts")).toBe(false);
    expect(isExempt("artifacts/other/report.md")).toBe(false);
  });
});

describe("parseProvenance", () => {
  it("reads the five-cell rows and ignores the hash tables", () => {
    const markdown = [
      "# heading",
      "| file | SHA256 | bytes |",
      "| --- | --- | --- |",
      "| report.md | abc | 12 |",
      HEADER,
      SEPARATOR,
      registryRow("datasets/aacr/samples/x.json", "AIza"),
      registryRow("artifacts/acceptance/rows.jsonl", "PRIVATE KEY", "romeokeita231/code-review-system", "self@30711d8"),
    ].join("\n");
    const { entries, problems } = parseProvenance(markdown);
    expect(problems).toEqual([]);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({ path: "datasets/aacr/samples/x.json", providers: ["AIza"], commit: "190d3bd" });
    expect(entries[1]!.commit).toBe("self@30711d8");
  });

  it("treats a broken row as a problem instead of silently dropping it", () => {
    const markdown = [
      HEADER,
      SEPARATOR,
      registryRow("research/x.json", "AKIA", "cline/cline", "not-a-commit"),
      registryRow("research/y.json", "nonsense", "cline/cline", "190d3bd"),
      registryRow("research/z.json", "AKIA", "not a repo", "190d3bd"),
      registryRow("research/w.json", "AKIA", "cline/cline", "190d3bd").replace("why the bytes are there", ""),
    ].join("\n");
    const { entries, problems } = parseProvenance(markdown);
    expect(entries).toHaveLength(0);
    expect(problems).toHaveLength(4);
    expect(problems.join(" ")).toContain("no commit");
    expect(problems.join(" ")).toContain("no known provider");
    expect(problems.join(" ")).toContain("no source repository");
    expect(problems.join(" ")).toContain("no note");
  });

  it("rejects a path that is absolute or climbs out of the repository", () => {
    const markdown = [
      HEADER,
      SEPARATOR,
      registryRow("/etc/passwd", "AKIA"),
      registryRow("research/../../outside.json", "AKIA"),
    ].join("\n");
    const { entries, problems } = parseProvenance(markdown);
    expect(entries).toHaveLength(0);
    expect(problems).toHaveLength(2);
  });
});

const hit = (path: string, provider: keyof typeof SAMPLES, count = 1): Hit => ({ path, provider, count });

const gateOk = (checks: ReturnType<typeof evaluateSecretGate>, name: string): boolean =>
  checks.find((check) => check.name === name)?.ok ?? false;

describe("evaluateSecretGate", () => {
  it("fails layer 1 on a provider shape outside the exempt zones", () => {
    const checks = evaluateSecretGate({
      hits: [hit("src/l2/orchestrator.ts", "sk")],
      entries: [],
      trackedCount: 10,
    });
    expect(gateOk(checks, "secret outside exempt zones")).toBe(false);
    expect(checks.find((check) => check.name === "secret outside exempt zones")?.detail).toContain(
      "src/l2/orchestrator.ts",
    );
    // Nothing was found inside the zones, so layer 2 has nothing to answer for.
    expect(gateOk(checks, "secret in exempt zones")).toBe(true);
  });

  it("passes layer 2 when the exempt-zone hit is registered, and prints the hit anyway", () => {
    const file = "datasets/aacr/samples/aacr-ts-0003.json";
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(file, "AIza")].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(file, "AIza", 3)],
      entries,
      trackedCount: 10,
    });
    expect(gateOk(checks, "secret outside exempt zones")).toBe(true);
    expect(gateOk(checks, "secret in exempt zones")).toBe(true);
    const detail = checks.find((check) => check.name === "secret in exempt zones")?.detail ?? "";
    expect(detail).toContain(`AIza ${file} ×3`);
  });

  it("fails layer 2 when the exempt-zone hit is not in the registry", () => {
    const file = "research/semgrep-bench/_raw_core_py.json";
    const checks = evaluateSecretGate({
      hits: [hit(file, "AKIA")],
      entries: [],
      trackedCount: 10,
    });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
    const detail = checks.find((check) => check.name === "secret in exempt zones")?.detail ?? "";
    expect(detail).toContain("unregistered");
    expect(detail).toContain(file);
    expect(detail).toContain("artifacts/acceptance/PROVENANCE.md");
  });

  it("fails layer 2 when a row is registered for a different provider", () => {
    const file = "datasets/self-built/samples/ts-cwe798-0001.json";
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(file, "AIza")].join("\n"));
    const checks = evaluateSecretGate({ hits: [hit(file, "PRIVATE KEY")], entries, trackedCount: 10 });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
  });

  it("fails layer 2 on a registry problem even when every hit has a row", () => {
    const file = "research/x.json";
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(file, "AKIA")].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(file, "AKIA")],
      entries,
      problems: ["line 9: research/x.json has no commit"],
      trackedCount: 10,
    });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
    expect(checks.find((check) => check.name === "secret in exempt zones")?.detail).toContain("registry problems");
  });

  it("keeps the literal-value check, and omits it when the key is not in the environment", () => {
    const withKey = evaluateSecretGate({
      hits: [],
      entries: [],
      envKeyMatches: ["src/config/index.ts"],
      trackedCount: 10,
    });
    expect(gateOk(withKey, "secret not tracked")).toBe(false);

    const clean = evaluateSecretGate({ hits: [], entries: [], envKeyMatches: [], trackedCount: 10 });
    expect(gateOk(clean, "secret not tracked")).toBe(true);

    const withoutKey = evaluateSecretGate({ hits: [], entries: [], envKeyMatches: null, trackedCount: 10 });
    expect(withoutKey.some((check) => check.name === "secret not tracked")).toBe(false);
  });

  it("scans files, reporting the ones it could not read instead of hiding them", () => {
    const { hits, skipped } = scanFiles([
      { path: "src/a.ts", text: SAMPLES.sk, skipped: false },
      { path: "datasets/x.json", text: SAMPLES.AIza, skipped: false },
      { path: "research/huge.json", text: "", skipped: true },
    ]);
    expect(hits.map((entry) => entry.path)).toEqual(["src/a.ts", "datasets/x.json"]);
    expect(skipped).toEqual(["research/huge.json"]);
  });
});
