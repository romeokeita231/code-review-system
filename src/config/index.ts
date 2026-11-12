import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { CalibrationArtifact, RunConfig, type Baseline } from "../contracts/index.js";

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

export function stableStringify(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${stableStringify(v)}`).join(",")}}`;
}

export function sha256(text: string): string {
  return createHash("sha256").update(text).digest("hex");
}

export function configHash(config: RunConfig): string {
  return sha256(stableStringify(config));
}

export function parseConfig(raw: unknown, origin = "<inline>"): RunConfig {
  const parsed = RunConfig.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `${i.path.join(".") || "<root>"}: ${i.message}`)
      .join("; ");
    throw new ConfigError(`invalid RunConfig at ${origin}: ${issues}`);
  }
  return parsed.data;
}

export async function loadConfig(path: string): Promise<RunConfig> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new ConfigError(`cannot read config ${path}: ${(error as Error).message}`);
  }
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (error) {
    throw new ConfigError(`config is not valid JSON ${path}: ${(error as Error).message}`);
  }
  return parseConfig(raw, path);
}

export async function loadCalibration(path: string): Promise<CalibrationArtifact> {
  let text: string;
  try {
    text = await readFile(path, "utf8");
  } catch (error) {
    throw new ConfigError(`cannot read calibration artifact ${path}: ${(error as Error).message}`);
  }
  const parsed = CalibrationArtifact.safeParse(JSON.parse(text));
  if (!parsed.success) {
    throw new ConfigError(`invalid calibration artifact ${path}: ${parsed.error.message}`);
  }
  return parsed.data;
}

export interface CalibrationExpectation {
  datasetVersion?: string;
  rulesetFingerprint?: string;
  /** The categories derived for *this* dataset + ruleset; compared exactly. */
  categories?: string[];
}

/**
 * #7 D2: a calibration artifact is only valid for the dataset and ruleset it was
 * fitted on. A mismatched version, fingerprint, or category list is a hard
 * failure, not a warning: the artifact carries per-category thresholds, so a
 * stale one silently applies a threshold that was fitted on another class set
 * (the old artifact still had `CWE-502`, which §6 replaced with `CWE-918`).
 */
export function assertCalibrationMatches(
  artifact: CalibrationArtifact,
  expected: CalibrationExpectation,
): void {
  if (
    expected.datasetVersion !== undefined &&
    artifact.dataset_version !== expected.datasetVersion
  ) {
    throw new ConfigError(
      `calibration artifact fitted on dataset ${artifact.dataset_version}, expected ${expected.datasetVersion}`,
    );
  }
  if (
    expected.rulesetFingerprint !== undefined &&
    artifact.ruleset_fingerprint !== expected.rulesetFingerprint
  ) {
    throw new ConfigError(
      `calibration artifact fitted on ruleset ${artifact.ruleset_fingerprint.slice(0, 12)}, ` +
        `expected ${expected.rulesetFingerprint.slice(0, 12)}`,
    );
  }
  if (expected.categories !== undefined) {
    const want = [...expected.categories].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const got = [...artifact.categories].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const missing = want.filter((c) => !got.includes(c));
    const extra = got.filter((c) => !want.includes(c));
    if (missing.length > 0 || extra.length > 0) {
      const parts: string[] = [];
      if (missing.length > 0) parts.push(`missing ${missing.join(", ")}`);
      if (extra.length > 0) parts.push(`unfitted ${extra.join(", ")}`);
      throw new ConfigError(`calibration categories do not match the dataset: ${parts.join("; ")}`);
    }
  }
}

/**
 * A null threshold is a *state*, not a bad value. `assertCalibrationMatches`
 * only checks provenance, so an `unfittable` artifact with the right
 * `dataset_version`/`ruleset_fingerprint` is compliant; consumers propagate the
 * state instead of substituting a constant.
 */
export function thresholdState(artifact: CalibrationArtifact): "fitted" | "unfittable" {
  return artifact.thresholds.global.block === null && artifact.thresholds.global.warn === null
    ? "unfittable"
    : "fitted";
}

export interface LadderShape {
  semgrep: boolean;
  aor: boolean;
  fusion: boolean;
  triage: boolean;
}

export function ladderShape(config: RunConfig): LadderShape {
  return {
    semgrep: config.sources.semgrep.enabled,
    aor: config.sources.aor.enabled,
    fusion:
      config.fusionStages.merge &&
      config.fusionStages.conflict &&
      config.fusionStages.calibrate &&
      config.fusionStages.vote,
    triage: config.triage.enabled,
  };
}

const EXPECTED: Record<Baseline, LadderShape> = {
  B0: { semgrep: false, aor: false, fusion: false, triage: false },
  B1: { semgrep: true, aor: false, fusion: false, triage: false },
  B2: { semgrep: false, aor: true, fusion: false, triage: false },
  B3: { semgrep: true, aor: true, fusion: false, triage: false },
  B4g: { semgrep: true, aor: true, fusion: true, triage: false },
  B4: { semgrep: true, aor: true, fusion: true, triage: true },
  single: { semgrep: true, aor: false, fusion: true, triage: false },
};

export function assertLadderConsistent(config: RunConfig): void {
  const actual = ladderShape(config);
  const expected = EXPECTED[config.baseline];
  const drift = (Object.keys(expected) as (keyof LadderShape)[]).filter(
    (key) => actual[key] !== expected[key],
  );
  if (drift.length > 0) {
    throw new ConfigError(
      `baseline ${config.baseline} disagrees with assembly on: ${drift
        .map((k) => `${k} (expected ${expected[k]}, got ${actual[k]})`)
        .join(", ")}`,
    );
  }
}
