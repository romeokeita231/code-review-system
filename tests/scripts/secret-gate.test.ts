import { describe, expect, it } from "vitest";
import {
  checkAnchor,
  evaluateSecretGate,
  EXEMPT_ZONES,
  isExempt,
  parseProvenance,
  scanFiles,
  scanText,
  type FileFacts,
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

const SHA = "0".repeat(64);
const OTHER_SHA = "1".repeat(64);
const SAMPLE_HIT_PATH = "datasets/aacr/samples/x.json";
const FACTS: ReadonlyMap<string, FileFacts> = new Map([[SAMPLE_HIT_PATH, { sha256: SHA, bytes: 26_261 }]]);

const HEADER = "| file | provider | repo | introduced-by | byte-origin | anchor | note |";
const SEPARATOR = "| --- | --- | --- | --- | --- | --- | --- |";

const registryRow = (
  file: string,
  provider: string,
  overrides: {
    repo?: string;
    introducedBy?: string;
    byteOrigin?: string;
    anchor?: string;
    note?: string;
  } = {},
): string =>
  [
    "",
    file,
    provider,
    overrides.repo ?? "cline/cline",
    overrides.introducedBy ?? "self@190d3bd",
    overrides.byteOrigin ?? "upstream:cline/cline@190d3bd:src/services/auth/AuthService.ts",
    overrides.anchor ?? `sha256:${SHA}`,
    overrides.note ?? "why the bytes are there",
    "",
  ].join(" | ");

const hit = (path: string, provider: keyof typeof SAMPLES, count = 1, distinct = 1): Hit => ({
  path,
  provider,
  count,
  distinct,
});

const gateOk = (checks: ReturnType<typeof evaluateSecretGate>, name: string): boolean =>
  checks.find((check) => check.name === name)?.ok ?? false;

const detailOf = (checks: ReturnType<typeof evaluateSecretGate>, name: string): string =>
  checks.find((check) => check.name === name)?.detail ?? "";

describe("scanText", () => {
  it("counts every provider shape, not just the one the first scan looked for", () => {
    const text = Object.values(SAMPLES).join("\n");
    const counted = Object.fromEntries([...scanText(text)].map(([provider, found]) => [provider, found.count]));
    expect(counted).toEqual({
      sk: 1,
      AIza: 1,
      ghp: 1,
      github_pat: 1,
      xox: 1,
      AKIA: 1,
      "PRIVATE KEY": 1,
    });
  });

  it("separates occurrences from distinct values, because they are different denominators", () => {
    const text = `${SAMPLES.AIza} ${SAMPLES.AIza} ${SAMPLES.AIza}`;
    expect(scanText(text).get("AIza")).toEqual({ count: 3, distinct: 1 });

    const twoValues = `${SAMPLES.AIza} ${join("AI", "za", "Z".repeat(35))}`;
    expect(scanText(twoValues).get("AIza")).toEqual({ count: 2, distinct: 2 });
  });

  it("does not carry a match from one file into the next", () => {
    expect(scanText(SAMPLES.AKIA).get("AKIA")?.count).toBe(1);
    expect(scanText("nothing here").size).toBe(0);
    expect(scanText(SAMPLES.AKIA).get("AKIA")?.count).toBe(1);
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
  it("reads the seven-cell rows and ignores the hash tables", () => {
    const markdown = [
      "# heading",
      "| file | SHA256 | bytes |",
      "| --- | --- | --- |",
      "| report.md | abc | 12 |",
      HEADER,
      SEPARATOR,
      registryRow(SAMPLE_HIT_PATH, "AIza"),
      registryRow("artifacts/acceptance/rows.jsonl", "PRIVATE KEY", {
        repo: "romeokeita231/code-review-system",
        introducedBy: "self@30711d8",
        byteOrigin: "derived:runs/live/x/rows.jsonl",
        anchor: `sha256:${OTHER_SHA}`,
      }),
    ].join("\n");
    const { entries, problems } = parseProvenance(markdown);
    expect(problems).toEqual([]);
    expect(entries).toHaveLength(2);
    expect(entries[0]).toMatchObject({
      path: SAMPLE_HIT_PATH,
      providers: ["AIza"],
      repo: "cline/cline",
      introducedBy: "self@190d3bd",
      byteOrigin: "upstream:cline/cline@190d3bd:src/services/auth/AuthService.ts",
      anchor: `sha256:${SHA}`,
    });
    expect(entries[1]!.byteOrigin).toBe("derived:runs/live/x/rows.jsonl");
  });

  it("treats a broken row as a problem instead of silently dropping it", () => {
    const markdown = [
      HEADER,
      SEPARATOR,
      registryRow("research/a.json", "AKIA", { introducedBy: "190d3bd" }),
      registryRow("research/b.json", "nonsense"),
      registryRow("research/c.json", "AKIA", { repo: "not a repo" }),
      registryRow("research/d.json", "AKIA", { byteOrigin: "somewhere" }),
      registryRow("research/e.json", "AKIA", { byteOrigin: "upstream:cline/cline" }),
      registryRow("research/f.json", "AKIA", { anchor: "sha256:abc" }),
      registryRow("research/g.json", "AKIA", { note: "" }),
      registryRow("research/h.json", "AKIA", { anchor: "trust me" }),
    ].join("\n");
    const { entries, problems } = parseProvenance(markdown);
    expect(entries).toHaveLength(0);
    expect(problems).toHaveLength(8);
    const joined = problems.join(" ");
    expect(joined).toContain("does not say which commit introduced it");
    expect(joined).toContain("no known provider");
    expect(joined).toContain("no source repository");
    expect(joined).toContain("does not say where its bytes came from");
    expect(joined).toContain("says upstream but not repo@commit:path");
    expect(joined).toContain("no recomputable anchor");
    expect(joined).toContain("no note");
    expect(joined).toContain("has no recomputable anchor");
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

describe("checkAnchor", () => {
  const entry = (anchor: string) => ({
    path: SAMPLE_HIT_PATH,
    providers: ["AIza"],
    repo: "cline/cline",
    introducedBy: "self@190d3bd",
    byteOrigin: "upstream:cline/cline@190d3bd:x.ts",
    anchor,
    note: "n",
  });

  it("recomputes a sha256 anchor and reports a mismatch as a failure", () => {
    expect(checkAnchor(entry(`sha256:${SHA}`), { sha256: SHA, bytes: 1 })).toMatchObject({ ok: true, verified: true });
    const mismatch = checkAnchor(entry(`sha256:${OTHER_SHA}`), { sha256: SHA, bytes: 1 });
    expect(mismatch.ok).toBe(false);
    expect(mismatch.detail).toContain("table says");
  });

  it("recomputes a size anchor", () => {
    expect(checkAnchor(entry("bytes:26261"), { sha256: SHA, bytes: 26_261 })).toMatchObject({ ok: true, verified: true });
    expect(checkAnchor(entry("bytes:1"), { sha256: SHA, bytes: 26_261 }).ok).toBe(false);
  });

  it("refuses to call an upstream claim verified, and fails when there are no facts", () => {
    expect(checkAnchor(entry("upstream:cline/cline@190d3bd:x.ts"), undefined)).toMatchObject({
      ok: true,
      verified: false,
    });
    const noFacts = checkAnchor(entry(`sha256:${SHA}`), undefined);
    expect(noFacts.ok).toBe(false);
    expect(noFacts.detail).toContain("cannot be recomputed");
  });
});

describe("evaluateSecretGate", () => {
  it("fails layer 1 on a provider shape outside the exempt zones", () => {
    const checks = evaluateSecretGate({
      hits: [hit("src/l2/orchestrator.ts", "sk")],
      entries: [],
      trackedCount: 10,
    });
    expect(gateOk(checks, "secret outside exempt zones")).toBe(false);
    expect(detailOf(checks, "secret outside exempt zones")).toContain("src/l2/orchestrator.ts");
    // Nothing was found inside the zones, so layer 2 has nothing to answer for.
    expect(gateOk(checks, "secret in exempt zones")).toBe(true);
  });

  it("passes layer 2 when the hit is registered with a recomputable anchor, and prints both units", () => {
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(SAMPLE_HIT_PATH, "AIza")].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(SAMPLE_HIT_PATH, "AIza", 8, 3)],
      entries,
      trackedCount: 10,
      fileFacts: FACTS,
    });
    expect(gateOk(checks, "secret outside exempt zones")).toBe(true);
    expect(gateOk(checks, "secret in exempt zones")).toBe(true);
    const detail = detailOf(checks, "secret in exempt zones");
    expect(detail).toContain(`AIza ${SAMPLE_HIT_PATH} ×8 occurrences / 3 distinct`);
    expect(detail).toContain("1/1 anchor(s) recomputed here");
  });

  it("fails layer 2 when the hit is not in the registry", () => {
    const file = "research/semgrep-bench/_raw_core_py.json";
    const checks = evaluateSecretGate({ hits: [hit(file, "AKIA")], entries: [], trackedCount: 10 });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
    const detail = detailOf(checks, "secret in exempt zones");
    expect(detail).toContain("unregistered");
    expect(detail).toContain(file);
    expect(detail).toContain("artifacts/acceptance/PROVENANCE.md");
  });

  it("fails layer 2 when the registered anchor does not recompute", () => {
    const { entries } = parseProvenance([
      HEADER,
      SEPARATOR,
      registryRow(SAMPLE_HIT_PATH, "AIza", { anchor: `sha256:${OTHER_SHA}` }),
    ].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(SAMPLE_HIT_PATH, "AIza")],
      entries,
      trackedCount: 10,
      fileFacts: FACTS,
    });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
    expect(detailOf(checks, "secret in exempt zones")).toContain("anchors that do not recompute");
  });

  it("fails layer 2 when the file whose anchor must be checked was not read", () => {
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(SAMPLE_HIT_PATH, "AIza")].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(SAMPLE_HIT_PATH, "AIza")],
      entries,
      trackedCount: 10,
      fileFacts: new Map(),
    });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
  });

  it("fails layer 2 when a row is registered for a different provider", () => {
    const file = "datasets/self-built/samples/ts-cwe798-0001.json";
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(file, "AIza")].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(file, "PRIVATE KEY")],
      entries,
      trackedCount: 10,
      fileFacts: FACTS,
    });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
  });

  it("fails layer 2 on a registry problem even when every hit has a row", () => {
    const { entries } = parseProvenance([HEADER, SEPARATOR, registryRow(SAMPLE_HIT_PATH, "AIza")].join("\n"));
    const checks = evaluateSecretGate({
      hits: [hit(SAMPLE_HIT_PATH, "AIza")],
      entries,
      problems: ["line 9: research/x.json has no commit"],
      trackedCount: 10,
      fileFacts: FACTS,
    });
    expect(gateOk(checks, "secret in exempt zones")).toBe(false);
    expect(detailOf(checks, "secret in exempt zones")).toContain("registry problems");
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
