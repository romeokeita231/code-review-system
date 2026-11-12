import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import {
  assertCalibrationMatches,
  assertLadderConsistent,
  configHash,
  ConfigError,
  parseConfig,
  stableStringify,
} from "../../src/config/index.js";
import { calibrationCategories, type CalibrationArtifact, type RunConfig } from "../../src/contracts/index.js";

const raw = (name: string): unknown => JSON.parse(readFileSync(`configs/${name}.json`, "utf8"));
const load = (name: string): RunConfig => parseConfig(raw(name));

describe("config", () => {
  it("accepts every committed baseline config", () => {
    for (const name of ["b1", "b2", "b3", "b4g", "b4", "single"]) {
      const config = load(name);
      expect(() => assertLadderConsistent(config)).not.toThrow();
    }
  });

  it("rejects a config whose assembly disagrees with its baseline label", () => {
    const config = raw("b1") as RunConfig;
    config.sources.aor.enabled = true;
    const parsed = parseConfig(config);
    expect(() => assertLadderConsistent(parsed)).toThrow(ConfigError);
  });

  it("rejects B4 without triage and B4g with triage", () => {
    const b4 = raw("b4") as RunConfig;
    b4.triage.enabled = false;
    expect(() => assertLadderConsistent(parseConfig(b4))).toThrow(/B4 /);
    const b4g = raw("b4g") as RunConfig;
    b4g.triage.enabled = true;
    expect(() => assertLadderConsistent(parseConfig(b4g))).toThrow(/B4g /);
  });

  it("reports the offending path for invalid input", () => {
    const broken = raw("b4") as Record<string, unknown>;
    delete broken.budgets;
    expect(() => parseConfig(broken)).toThrow(/budgets/);
  });

  it("hashes configs independently of key order", () => {
    const config = load("b4");
    const reversed = Object.fromEntries(Object.entries(config).reverse());
    expect(stableStringify(config)).toBe(stableStringify(reversed));
    expect(configHash(parseConfig(reversed))).toBe(configHash(config));
  });

  it("changes the hash when any threshold or version moves", () => {
    const base = load("b4");
    const louder = parseConfig({ ...base, thresholds: { block: 0.91, warn: 0.7 } });
    const newer = parseConfig({ ...base, version: "1.0.1" });
    expect(configHash(louder)).not.toBe(configHash(base));
    expect(configHash(newer)).not.toBe(configHash(base));
  });

  it("keeps calibration version inside the hash", () => {
    const base = load("b4");
    const drifted = parseConfig({ ...base, calibration: { ...base.calibration, version: "calib-v2" } });
    expect(configHash(drifted)).not.toBe(configHash(base));
  });
});

describe("calibration provenance (#7 D2)", () => {
  const artifact = (over: Partial<CalibrationArtifact> = {}): CalibrationArtifact => ({
    version: "calib-test",
    dataset_version: "ds-2",
    ruleset_fingerprint: "fp",
    categories: ["CWE-22", "CWE-89"],
    pPrior: 0.3,
    shrinkageN0: 10,
    pMax: 0.95,
    fitRoot: "root",
    grids: [],
    thresholds: { global: { block: null, warn: null }, perCategory: {}, skipped: [] },
    ...over,
  });

  it("derives categories as dataset ∩ ruleset", () => {
    expect(calibrationCategories(["CWE-22", "CWE-502", "CWE-89"], ["022", "089", "918"])).toEqual([
      "CWE-22",
      "CWE-89",
    ]);
  });

  it("normalises zero padding and long CWE labels on both sides", () => {
    expect(
      calibrationCategories(
        ["CWE-022"],
        ["CWE-22: Improper Limitation of a Pathname to a Restricted Directory"],
      ),
    ).toEqual(["CWE-22"]);
    expect(calibrationCategories([null, "not-a-cwe"], ["022"])).toEqual([]);
  });

  it("returns an empty set when the dataset and the ruleset share no class", () => {
    expect(calibrationCategories(["CWE-502"], ["022", "089"])).toEqual([]);
  });

  it("accepts an artifact fitted on the same dataset and ruleset", () => {
    expect(() =>
      assertCalibrationMatches(artifact(), {
        datasetVersion: "ds-2",
        rulesetFingerprint: "fp",
        categories: ["CWE-89", "CWE-22"],
      }),
    ).not.toThrow();
  });

  it("hard-fails on a dataset version mismatch", () => {
    expect(() => assertCalibrationMatches(artifact(), { datasetVersion: "ds-3" })).toThrow(
      /dataset ds-2, expected ds-3/,
    );
  });

  it("hard-fails on a ruleset fingerprint mismatch", () => {
    expect(() => assertCalibrationMatches(artifact(), { rulesetFingerprint: "other" })).toThrow(
      /ruleset/,
    );
  });

  it("hard-fails when the artifact still carries a class the dataset lost", () => {
    expect(() =>
      assertCalibrationMatches(artifact({ categories: ["CWE-22", "CWE-502"] }), {
        categories: ["CWE-22", "CWE-89"],
      }),
    ).toThrow(/unfitted CWE-502/);
  });

  it("hard-fails when a declared class has no fitted grid", () => {
    expect(() =>
      assertCalibrationMatches(artifact({ categories: ["CWE-22"] }), {
        categories: ["CWE-22", "CWE-89"],
      }),
    ).toThrow(/missing CWE-89/);
  });

  it("recomputes the committed artifact's categories from the dataset and rules table", () => {
    const dataset = JSON.parse(readFileSync("datasets/self-built/manifest.json", "utf8")) as {
      samples: Array<{ cwe: string | null }>;
    };
    const table = JSON.parse(
      readFileSync("research/semgrep-bench/snapshot/rules_table.json", "utf8"),
    ) as { rules: Array<{ languages: string[]; cwe: string[] | null }> };
    const rulesetCwes = table.rules
      .filter((rule) => rule.languages.includes("typescript"))
      .flatMap((rule) => rule.cwe ?? []);
    const committed = JSON.parse(readFileSync("artifacts/calibration.json", "utf8")) as {
      categories: string[];
    };
    expect(committed.categories).toEqual(
      calibrationCategories(
        dataset.samples.map((sample) => sample.cwe),
        rulesetCwes,
      ),
    );
    // The drifted set is CWE-502; the ruleset never declared it, so it must not
    // survive in the artifact even though 75 recorded findings still carry it.
    expect(committed.categories).not.toContain("CWE-502");
  });
});
