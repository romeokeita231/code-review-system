import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { assertLadderConsistent, configHash, ConfigError, parseConfig, stableStringify } from "../../src/config/index.js";
import type { RunConfig } from "../../src/contracts/index.js";

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
