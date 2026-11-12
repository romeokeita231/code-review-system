import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { DatasetManifest, SourceName } from "../src/contracts/index.js";
import { CWES, diffCount, riskOf, type Cwe } from "./shared.js";

const EXPECTED_SAMPLE_COUNT = 420;
const EXPECTED_GROUPS = 210;
const EXPECTED_PER_CWE = 30;

const Label = z.object({
  path: z.string().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive(),
  cwe: z.string().regex(/^CWE-\d+$/).nullable(),
});

export const SampleFile = z.object({
  sample_id: z.string().min(1),
  group_id: z.string().min(1),
  split: z.enum(["fit", "eval"]),
  cwe: z.string().regex(/^CWE-\d+$/).nullable(),
  risk_level: z.enum(["low", "medium", "high"]),
  paired_safe: z.boolean(),
  language: z.string().min(1),
  path: z.string().min(1),
  before: z.string(),
  after: z.string(),
  changed_lines: z.number().int().nonnegative(),
  expected_detectable_by: z.array(SourceName),
  labels: z.array(Label),
});
export type SampleFile = z.infer<typeof SampleFile>;

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

const isCwe = (value: string | null): value is Cwe => value !== null && (CWES as readonly string[]).includes(value);

function lineCount(text: string): number {
  const parts = text.split("\n");
  return text.endsWith("\n") ? parts.length - 1 : parts.length;
}

interface Loaded {
  file: SampleFile;
  hash: string;
}

export interface VerifyResult {
  ok: boolean;
  errors: string[];
}

const errorText = (error: unknown): string => (error instanceof Error ? error.message : String(error));

export async function verifyDataset(dir: string): Promise<VerifyResult> {
  const errors: string[] = [];
  const manifestPath = join(dir, "manifest.json");
  const samplesDir = join(dir, "samples");

  let manifest: DatasetManifest;
  try {
    const parsed = DatasetManifest.safeParse(JSON.parse(await readFile(manifestPath, "utf8")));
    if (!parsed.success) {
      return {
        ok: false,
        errors: [`manifest: schema validation failed: ${parsed.error.issues[0]?.message ?? "unknown"}`],
      };
    }
    manifest = parsed.data;
  } catch (error) {
    return { ok: false, errors: [`manifest: cannot read ${manifestPath}: ${errorText(error)}`] };
  }

  let fileNames: string[];
  try {
    fileNames = (await readdir(samplesDir)).filter((name) => name.endsWith(".json")).sort();
  } catch (error) {
    return { ok: false, errors: [`samples: cannot read ${samplesDir}: ${errorText(error)}`] };
  }

  const loaded = new Map<string, Loaded>();
  for (const name of fileNames) {
    let data: unknown;
    try {
      data = JSON.parse(await readFile(join(samplesDir, name), "utf8"));
    } catch (error) {
      errors.push(`samples/${name}: invalid JSON: ${errorText(error)}`);
      continue;
    }
    const parsed = SampleFile.safeParse(data);
    if (!parsed.success) {
      errors.push(`samples/${name}: schema invalid: ${parsed.error.issues[0]?.message ?? "unknown"}`);
      continue;
    }
    const file = parsed.data;
    if (name !== `${file.sample_id}.json`) {
      errors.push(`samples/${name}: filename does not match sample_id ${file.sample_id}`);
    }
    if (loaded.has(file.sample_id)) {
      errors.push(`duplicate sample_id ${file.sample_id}`);
    }
    loaded.set(file.sample_id, { file, hash: sha256(`${file.before}\u0000${file.after}`) });
  }

  if (fileNames.length !== EXPECTED_SAMPLE_COUNT) {
    errors.push(`sample count: expected ${EXPECTED_SAMPLE_COUNT} files, got ${fileNames.length}`);
  }
  if (loaded.size !== EXPECTED_SAMPLE_COUNT) {
    errors.push(`sample count: expected ${EXPECTED_SAMPLE_COUNT} parsed samples, got ${loaded.size}`);
  }

  for (const { file } of loaded.values()) {
    if (file.before.includes("\r") || file.after.includes("\r")) {
      errors.push(`${file.sample_id}: content must use LF line endings`);
    }
    if (!file.before.endsWith("\n") || !file.after.endsWith("\n")) {
      errors.push(`${file.sample_id}: content must end with a trailing LF`);
    }
    if (file.language !== "ts") {
      errors.push(`${file.sample_id}: language must be "ts"`);
    }
    if (file.expected_detectable_by.length === 0) {
      errors.push(`${file.sample_id}: expected_detectable_by must not be empty`);
    }
    if (file.paired_safe ? file.labels.length !== 0 : file.labels.length !== 1) {
      errors.push(`${file.sample_id}: labels must be exactly one entry for main samples and none for safe samples`);
    }
    const beforeLines = file.before.endsWith("\n") ? file.before.slice(0, -1).split("\n") : file.before.split("\n");
    const afterLines = file.after.endsWith("\n") ? file.after.slice(0, -1).split("\n") : file.after.split("\n");
    const actualChanged = diffCount(beforeLines, afterLines);
    if (actualChanged !== file.changed_lines) {
      errors.push(`${file.sample_id}: changed_lines ${file.changed_lines} != actual ${actualChanged}`);
    }
    if (isCwe(file.cwe)) {
      const expectedRisk = riskOf(file.cwe, file.changed_lines);
      if (expectedRisk !== file.risk_level) {
        errors.push(`${file.sample_id}: risk_level ${file.risk_level} != derived ${expectedRisk}`);
      }
    } else {
      errors.push(`${file.sample_id}: cwe ${String(file.cwe)} is not an annotated category`);
    }
    const limit = lineCount(file.after);
    for (const label of file.labels) {
      if (label.path !== file.path) {
        errors.push(`${file.sample_id}: label path ${label.path} != sample path ${file.path}`);
      }
      if (label.cwe !== file.cwe) {
        errors.push(`${file.sample_id}: label cwe ${String(label.cwe)} != sample cwe ${String(file.cwe)}`);
      }
      if (label.startLine < 1 || label.endLine < label.startLine || label.endLine > limit) {
        errors.push(
          `${file.sample_id}: label ${label.startLine}-${label.endLine} outside file bounds 1-${limit}`,
        );
      }
    }
  }

  const manifestIds = new Set(manifest.samples.map((sample) => sample.sample_id));
  if (manifest.samples.length !== EXPECTED_SAMPLE_COUNT) {
    errors.push(`manifest: expected ${EXPECTED_SAMPLE_COUNT} entries, got ${manifest.samples.length}`);
  }
  for (const sample of manifest.samples) {
    if (!loaded.has(sample.sample_id)) {
      errors.push(`manifest: missing sample file for ${sample.sample_id}`);
    }
  }
  for (const id of loaded.keys()) {
    if (!manifestIds.has(id)) {
      errors.push(`manifest: sample file ${id} is not listed`);
    }
  }

  const rootLines: string[] = [];
  for (const entry of manifest.samples) {
    const record = loaded.get(entry.sample_id);
    if (!record) continue;
    if (record.hash !== entry.content_sha256) {
      errors.push(
        `content hash mismatch for ${entry.sample_id}: manifest ${entry.content_sha256} != actual ${record.hash}`,
      );
    }
    const fields = [
      "group_id",
      "split",
      "cwe",
      "risk_level",
      "paired_safe",
      "language",
      "path",
      "changed_lines",
      "expected_detectable_by",
    ] as const;
    for (const field of fields) {
      if (JSON.stringify(record.file[field]) !== JSON.stringify(entry[field])) {
        errors.push(`manifest/file mismatch for ${entry.sample_id}: ${field}`);
      }
    }
    rootLines.push(`${entry.sample_id}:${record.hash}`);
  }

  rootLines.sort();
  const actualRoot = sha256(rootLines.join("\n"));
  if (actualRoot !== manifest.content_sha256_root) {
    errors.push(
      `root hash drift: manifest ${manifest.content_sha256_root} != actual ${actualRoot}`,
    );
  }
  const declaredRoot = sha256(
    manifest.samples
      .map((sample) => `${sample.sample_id}:${sample.content_sha256}`)
      .sort()
      .join("\n"),
  );
  if (declaredRoot !== manifest.content_sha256_root) {
    errors.push(`root hash mismatch: declared entries hash to ${declaredRoot}`);
  }

  const groups = new Map<string, SampleFile[]>();
  for (const { file } of loaded.values()) {
    const bucket = groups.get(file.group_id) ?? [];
    bucket.push(file);
    groups.set(file.group_id, bucket);
  }
  if (groups.size !== EXPECTED_GROUPS) {
    errors.push(`group count: expected ${EXPECTED_GROUPS}, got ${groups.size}`);
  }
  for (const [groupId, bucket] of groups) {
    if (bucket.length !== 2) {
      errors.push(`group ${groupId}: expected 2 samples, got ${bucket.length}`);
      continue;
    }
    const main = bucket.find((sample) => !sample.paired_safe);
    const safe = bucket.find((sample) => sample.paired_safe);
    if (!main || !safe) {
      errors.push(`group ${groupId}: missing main or paired safe variant`);
      continue;
    }
    if (safe.sample_id !== `${main.sample_id}-safe`) {
      errors.push(`group ${groupId}: safe sample_id ${safe.sample_id} is not ${main.sample_id}-safe`);
    }
    if (main.cwe !== safe.cwe) {
      errors.push(`group ${groupId}: main/safe cwe differ`);
    }
    if (safe.labels.length !== 0) {
      errors.push(`group ${groupId}: paired safe variant carries labels`);
    }
    if (main.split !== safe.split) {
      errors.push(`split leakage in group ${groupId}: main=${main.split} safe=${safe.split}`);
    }
  }

  const perCwe = new Map<Cwe, { fit: number; eval: number }>();
  for (const { file } of loaded.values()) {
    if (file.paired_safe || !isCwe(file.cwe)) continue;
    const bucket = perCwe.get(file.cwe) ?? { fit: 0, eval: 0 };
    bucket[file.split] += 1;
    perCwe.set(file.cwe, bucket);
  }
  let totalFit = 0;
  let totalGroups = 0;
  for (const cwe of CWES) {
    const bucket = perCwe.get(cwe);
    if (!bucket) {
      errors.push(`split: ${cwe} has no samples`);
      continue;
    }
    if (bucket.fit === 0 || bucket.eval === 0) {
      errors.push(`split: ${cwe} is missing a split (fit=${bucket.fit} eval=${bucket.eval})`);
    }
    if (bucket.fit + bucket.eval !== EXPECTED_PER_CWE) {
      errors.push(`split: ${cwe} has ${bucket.fit + bucket.eval} groups, expected ${EXPECTED_PER_CWE}`);
    }
    if (bucket.fit < 6 || bucket.eval < 6) {
      errors.push(`per-CWE split ratio out of band for ${cwe}: fit=${bucket.fit} eval=${bucket.eval}`);
    }
    totalFit += bucket.fit;
    totalGroups += bucket.fit + bucket.eval;
  }
  if (totalGroups > 0) {
    const share = totalFit / totalGroups;
    if (share < 0.54 || share > 0.66) {
      errors.push(`global fit/eval ratio out of band: fit=${totalFit} total=${totalGroups}`);
    }
  }

  return { ok: errors.length === 0, errors };
}

const invokedDirectly = (): boolean => {
  const entry = process.argv[1];
  if (!entry) return false;
  return resolve(entry).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
};

/* -------------------------------------------------------------------------
 * Annotation-spec conformance (issue #7 §13)
 *
 * `verifyDataset` above validates the dataset against its own manifest: hashes,
 * counts, pairing, split leakage. That is *self*-consistency, and a dataset
 * whose schema drifted from the spec passes it perfectly - which is exactly the
 * failure this repo hit: `cwe` instead of `sample_cwe`, `paired_safe` instead
 * of `variant_of`, `medium` risk levels, an `expected_detectable_by` array, and
 * CWE-502 living where §6 says CWE-918 should be.
 *
 * Conformance validates against the spec text instead of the dataset's current
 * shape. It is meant to fail, loudly, until the dataset is rebuilt (P2).
 *
 * The `noop` / `rationale` / `variant` / `version` rules are the #7 errata ("D1"
 * in #41): a sample has to be a real change, a safe variant has to name the
 * control that makes it safe, and the rebuilt set is schema_version 2 / `ds-2`.
 * Without them the negatives are free to be no-op writes, which is how the old
 * set produced a precision denominator that was true by construction.
 * ---------------------------------------------------------------------- */

/** §6: the seven annotated classes. CWE-502 is not one of them. */
export const SPEC_CWES = ["022", "078", "079", "089", "094", "798", "918"] as const;

/** §13: `sample_set` enum. The spec spells CWE-Bench "cwebrench" in two
 * places; both readings are accepted so the typo does not mask real drift. */
export const SPEC_SAMPLE_SETS = ["self", "aacr", "securityeval", "cwebench", "cwebrench"];

const DefectSpec = z.object({
  defect_id: z.string().min(1),
  cwe: z.string().nullable(),
  file: z.string().min(1),
  line_start: z.number().int().positive(),
  line_end: z.number().int().positive(),
  symbol: z.string().nullable(),
  evidence: z.string().min(1),
});

/** ConformanceSample row. `schema_version` 1 is the drifted set, 2 is the #7
 * errata shape (real diff + named control on every safe variant). */
export const ConformanceSample = z
  .object({
    sample_id: z.string().min(1),
    schema_version: z.union([z.literal(1), z.literal(2)]),
    unit: z.literal("file_write"),
    language: z.enum(["ts", "js", "tsx", "jsx"]),
    sample_set: z.enum(["self", "aacr", "securityeval", "cwebench", "cwebrench"]),
    group_id: z.string().min(1),
    repo: z.string().min(1),
    file_path: z.string().min(1),
    before: z.string(),
    after: z.string(),
    label: z.union([z.literal(0), z.literal(1)]).optional(),
    defects: z.array(DefectSpec),
    sample_cwe: z.string().regex(/^CWE-\d+$/).nullable(),
    variant_of: z.string().nullable(),
    /** §13 errata: required on `variant_of` rows; must name the control. */
    rationale: z.string().nullable().optional(),
    expected_detectable_by: z.enum(["both", "semgrep_only", "aor_only"]).nullable(),
    risk_level: z.enum(["low", "high"]),
    contamination_risk: z.enum(["low", "high"]),
    origin: z.object({
      kind: z.enum(["public_repo", "self_rewritten", "aacr", "securityeval", "cwebrench", "cwebench"]),
      ref: z.string().min(1),
      advisory: z.string().nullable(),
    }),
    annotator: z.enum(["self", "advisor"]).nullable(),
  })
  .strict();
export type ConformanceSample = z.infer<typeof ConformanceSample>;

export interface Violation {
  rule: string;
  sample: string | null;
  detail: string;
}

export interface ConformanceSummary {
  rule: string;
  count: number;
  examples: string[];
}

export interface ConformanceResult {
  ok: boolean;
  samples: number;
  violations: Violation[];
  summary: ConformanceSummary[];
}

const RULE_ORDER = [
  "json",
  "schema",
  "version",
  "sample_id",
  "noop",
  "rationale",
  "risk_level",
  "defects",
  "variant",
  "contamination",
  "annotator",
  "classes",
  "split_ratio",
] as const;

const str = (value: unknown): string | null => (typeof value === "string" ? value : null);
const asRecord = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
const asList = (value: unknown): unknown[] => (Array.isArray(value) ? value : []);

/** Lines that carry no behaviour: comments and blanks. */
const COMMENT_LINE = /^\s*(\/\/|\/\*|\*|\*\/|#)/;

/**
 * D1: a diff must touch at least one line that is not a comment or blank.
 *
 * Compared on the changed window only (common prefix/suffix stripped), so a
 * reformat that only moves a comment around is still called out.
 */
export function substantiveChange(before: string, after: string): boolean {
  const a = before.split("\n");
  const b = after.split("\n");
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start += 1;
  let endA = a.length - 1;
  let endB = b.length - 1;
  while (endA >= start && endB >= start && a[endA] === b[endB]) {
    endA -= 1;
    endB -= 1;
  }
  const changed = [...a.slice(start, endA + 1), ...b.slice(start, endB + 1)];
  return changed.some((line) => line.trim().length > 0 && !COMMENT_LINE.test(line));
}

/** Things people write when they have not identified a control. */
const NOT_A_CONTROL = new RegExp(
  "^(?:已?修改|已?修复|已?调整|已?变更|已?改动|改好了|" +
    "changed?|modified|fixed|updated|patched|refactored|tweak(?:ed)?|adjusted|" +
    "no[-\\s]?op|no[-\\s]?change|none|n/?a|todo|misc|same|safe(?:\\s+version)?|变体)$",
  "i",
);

/**
 * D1: `rationale` must be a control name (参数化 / 路径包含校验 / 转义 / 白名单 /
 * 移除 sink), not "已修改". Only the degenerate answers are machine-detectable;
 * whether the named control actually holds is the annotator's job (§5).
 */
export function isControlName(text: string): boolean {
  const normalized = text.trim().replace(/\s+/g, " ");
  if (normalized.length < 3) return false;
  if (NOT_A_CONTROL.test(normalized)) return false;
  return /\p{L}/u.test(normalized);
}

/**
 * The spec's `sample_cwe`, read with a fallback to the pre-spec name `cwe`.
 * Diagnostics (risk derivation, class table, split ratio) still work on a
 * drifted dataset; the strict schema reports the rename separately, so the
 * fallback never hides it - it just lets the other rules keep running.
 */
const sampleCweOf = (raw: Record<string, unknown>): string | null =>
  str(raw["sample_cwe"]) ?? str(raw["cwe"]);

/** §9: low iff the class is 079/798 and the change is at most 30 lines, else high. */
export function specRiskLevel(sampleCwe: string | null, changedLines: number): "low" | "high" {
  const key = sampleCwe === null ? null : sampleCwe.replace(/^CWE-/i, "").padStart(3, "0");
  const low = (key === "079" || key === "798") && changedLines <= 30;
  return low ? "low" : "high";
}

/** §13: `{lang}-cwe{NNN}-{seq}`, or `aacr-{lang}-{seq}` for AACR rows. */
export function specSampleId(id: string, sampleSet: string): boolean {
  if (sampleSet === "aacr") return /^aacr-(ts|js|tsx|jsx)-\d{4}$/.test(id);
  return /^(ts|js|tsx|jsx)-cwe\d{3}-\d{4}$/.test(id);
}

export async function verifyConformance(dir: string): Promise<ConformanceResult> {
  const violations: Violation[] = [];
  const add = (rule: Violation["rule"], sample: string | null, detail: string): void => {
    violations.push({ rule, sample, detail });
  };

  // Read the manifest leniently: `split` and `version` are the only things
  // conformance needs from it, and validating it against the *current* contract
  // schema would make this check inherit the very drift it is meant to catch.
  let manifest: { version: string; samples: Array<{ sample_id: string; split?: string }> };
  try {
    const parsed = JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")) as unknown;
    const samples = asRecord(parsed)["samples"];
    if (!Array.isArray(samples)) throw new Error("manifest has no `samples` array");
    manifest = {
      version: str(asRecord(parsed)["version"]) ?? "",
      samples: samples.map((entry) => ({
        sample_id: str(asRecord(entry)["sample_id"]) ?? "",
        split: str(asRecord(entry)["split"]) ?? undefined,
      })),
    };
  } catch (error) {
    return {
      ok: false,
      samples: 0,
      violations: [{ rule: "json", sample: null, detail: `manifest: ${errorText(error)}` }],
      summary: [{ rule: "json", count: 1, examples: [errorText(error)] }],
    };
  }

  const splits = new Map(manifest.samples.map((entry) => [entry.sample_id, entry.split]));
  const fileNames = (await readdir(join(dir, "samples"))).filter((name) => name.endsWith(".json")).sort();
  const records = new Map<string, Record<string, unknown>>();
  const defectsById = new Map<string, number>();

  for (const name of fileNames) {
    let raw: Record<string, unknown>;
    try {
      raw = asRecord(JSON.parse(await readFile(join(dir, "samples", name), "utf8")));
    } catch (error) {
      add("json", name, errorText(error));
      continue;
    }
    const id = str(raw["sample_id"]) ?? name.replace(/\.json$/, "");
    records.set(id, raw);
    if (name !== `${id}.json`) add("sample_id", id, `filename ${name} does not match sample_id`);

    const parsed = ConformanceSample.safeParse(raw);
    if (!parsed.success) {
      // Renamed or leftover fields are the sharpest drift signal, so surface
      // them before the "missing field" noise they inevitably cause.
      const unknown = parsed.error.issues.find((issue) => issue.code === "unrecognized_keys");
      if (unknown !== undefined) {
        const keys = (unknown as { keys?: string[] }).keys ?? [];
        add("schema", id, `unrecognized keys: ${keys.join(", ")}`);
      }
      const rest = parsed.error.issues.filter((issue) => issue.code !== "unrecognized_keys");
      // One row can be wrong in eight ways; three examples are enough to name
      // the drift, and the count is reported in the summary either way.
      for (const issue of rest.slice(0, 3)) {
        const where = issue.path.length > 0 ? `${issue.path.join(".")}: ` : "";
        add("schema", id, `${where}${issue.message}`);
      }
      if (rest.length > 3) {
        add("schema", id, `(+${rest.length - 3} more schema issues)`);
      }
    }

    const sampleSet = str(raw["sample_set"]) ?? "self";
    if (!specSampleId(id, sampleSet)) {
      add("sample_id", id, `id ${id} does not match the §13 pattern for sample_set=${sampleSet}`);
    }

    defectsById.set(id, asList(raw["defects"]).length);

    // #7 errata: schema_version 1 is the drifted shape; the rebuilt set is 2.
    const schemaVersion = raw["schema_version"];
    if (sampleSet === "self" && schemaVersion !== 2) {
      add("version", id, `self row schema_version=${String(schemaVersion)} != 2`);
    }
    if (sampleSet !== "self" && schemaVersion !== 1) {
      add("version", id, `external row schema_version=${String(schemaVersion)} != 1`);
    }

    const before = str(raw["before"]) ?? "";
    const after = str(raw["after"]) ?? "";
    const changedLines = diffCount(
      before.endsWith("\n") ? before.slice(0, -1).split("\n") : before.split("\n"),
      after.endsWith("\n") ? after.slice(0, -1).split("\n") : after.split("\n"),
    );

    // D1: a sample has to be a real change. All 210 old "safe variants" were
    // no-op writes (`before === after`), which makes the precision denominator
    // vacuously true - the FP half of line 1 measured nothing.
    if (sha256(before) === sha256(after)) {
      add("noop", id, "before === after: a no-op write is not a sample");
    } else if (!substantiveChange(before, after)) {
      add("noop", id, "diff touches only comments/blank lines");
    }

    // D1: a safe variant must name the control that makes it safe.
    const variantId = str(raw["variant_of"]);
    if (variantId !== null) {
      const rationale = str(raw["rationale"]);
      if (rationale === null) {
        add("rationale", id, "variant row is missing `rationale`");
      } else if (!isControlName(rationale)) {
        add("rationale", id, `rationale "${rationale}" names no control`);
      }
    }

    const sampleCwe = sampleCweOf(raw);
    const declaredRisk = str(raw["risk_level"]);
    if (declaredRisk !== null) {
      const derived = specRiskLevel(sampleCwe, changedLines);
      if (declaredRisk !== derived) {
        add("risk_level", id, `${declaredRisk} != §9 derivation ${derived} (cwe=${sampleCwe ?? "null"} lines=${changedLines})`);
      }
    }

    // §13: `label` exists only on AACR rows and must agree with `defects`.
    const hasLabel = raw["label"] !== undefined;
    if (sampleSet !== "aacr" && hasLabel) add("defects", id, "non-AACR row carries `label`");
    if (sampleSet === "aacr") {
      if (!hasLabel) add("defects", id, "AACR row is missing `label`");
      else {
        const label = raw["label"];
        const populated = asList(raw["defects"]).length > 0;
        if ((label === 1) !== populated) add("defects", id, `label ${String(label)} disagrees with defects`);
      }
      if (sampleCwe !== null) add("defects", id, `AACR row must have sample_cwe=null, got ${sampleCwe}`);
    } else if (sampleCwe === null) {
      add("defects", id, "non-AACR row must carry sample_cwe");
    }

    const afterCount = after.endsWith("\n") ? after.split("\n").length - 1 : after.split("\n").length;
    const filePath = str(raw["file_path"]);
    for (const [index, defectRaw] of asList(raw["defects"]).entries()) {
      const defect = asRecord(defectRaw);
      const defectId = str(defect["defect_id"]) ?? "";
      const start = typeof defect["line_start"] === "number" ? defect["line_start"] : null;
      const end = typeof defect["line_end"] === "number" ? defect["line_end"] : null;
      if (defectId !== `${id}#d${index + 1}`) {
        add("defects", id, `defect_id ${defectId || "(missing)"} should be ${id}#d${index + 1}`);
      }
      if (defect["file"] !== filePath) add("defects", id, `defect ${defectId} file != file_path`);
      if (start === null || end === null || end < start) {
        add("defects", id, `defect ${defectId} has an unusable span ${String(start)}-${String(end)}`);
        continue;
      }
      // §13: the span is the smallest syntactic unit; > 3 lines is a lazy label.
      // That is a rule about how *we* annotate, so it does not apply to imported
      // AACR rows - §11 says their from/to are comment positions and AACR's own
      // metric scores by range overlap, not by a tight span.
      if (end - start + 1 > 3 && sampleSet !== "aacr") {
        add("defects", id, `defect ${defectId} spans ${end - start + 1} lines (> 3)`);
      }
      if (start < 1 || end > afterCount) {
        add("defects", id, `defect ${defectId} span ${start}-${end} outside after bounds 1-${afterCount}`);
      }
      if (sampleSet !== "aacr" && defect["cwe"] !== sampleCwe) {
        add("defects", id, `defect ${defectId} cwe != sample_cwe`);
      }
    }

    const origin = asRecord(raw["origin"]);
    const contamination = str(raw["contamination_risk"]);
    if (contamination === "high") {
      if (origin["kind"] !== "public_repo" || str(origin["advisory"]) === null) {
        add("contamination", id, "contamination_risk=high needs kind=public_repo and an advisory id");
      }
    }

    const annotator = raw["annotator"];
    if (sampleSet !== "self" && annotator !== null) {
      add("annotator", id, `external row must have annotator=null, got ${String(annotator)}`);
    }
  }

  for (const [id, raw] of records) {
    const variant = str(raw["variant_of"]);
    if (variant === null) continue;
    if (!records.has(variant)) {
      add("variant", id, `variant_of ${variant} does not exist`);
      continue;
    }
    if (splits.get(variant) !== splits.get(id)) {
      add("variant", id, `variant_of ${variant} sits in another split (${String(splits.get(variant))} vs ${String(splits.get(id))})`);
    }
    const main = records.get(variant)!;
    // D1: a variant that drifted onto another file or class is not the same
    // defect with a control added - it is a different sample wearing the label.
    if (str(main["file_path"]) !== str(raw["file_path"])) {
      add(
        "variant",
        id,
        `variant_of ${variant} sits on another file (${String(raw["file_path"])} != ${String(main["file_path"])})`,
      );
    }
    if (sampleCweOf(main) !== sampleCweOf(raw)) {
      add(
        "variant",
        id,
        `variant_of ${variant} has sample_cwe ${String(sampleCweOf(raw))} != ${String(sampleCweOf(main))}`,
      );
    }
    if ((defectsById.get(id) ?? 0) > 0) add("variant", id, "a paired safe variant must have defects=[]");
    if ((defectsById.get(variant) ?? 0) === 0) add("variant", id, `variant_of ${variant} is not a defective row`);
  }

  const selfRecords = [...records].filter(([, raw]) => (str(raw["sample_set"]) ?? "self") === "self");
  // §6 / §7 describe the self-built set. A pure external set (e.g. the AACR
  // import) has no CWE and no per-class split, so those rules do not apply to
  // it - they are skipped rather than reported as a hundred violations.
  if (selfRecords.length > 0) {
    // #7 errata: the rebuilt self-built set is `ds-2`. A manifest still on the
    // old version cannot be the set these rules describe.
    if (!manifest.version.startsWith("ds-2")) {
      add("version", null, `self-built manifest version "${manifest.version}" is not ds-2`);
    }
    const classes = new Set(
      selfRecords.map(([, raw]) => {
        const cwe = sampleCweOf(raw);
        return cwe === null ? "null" : cwe.replace(/^CWE-/i, "").padStart(3, "0");
      }),
    );
    for (const cwe of SPEC_CWES) {
      if (!classes.has(cwe)) add("classes", null, `§6 class CWE-${cwe} has no samples`);
    }
    for (const cwe of classes) {
      if (!(SPEC_CWES as readonly string[]).includes(cwe)) {
        add("classes", null, `CWE-${cwe} is not one of the §6 classes`);
      }
    }
  }

  const ratio = new Map<string, { fit: number; eval: number }>();
  for (const [id, raw] of selfRecords) {
    const cwe = sampleCweOf(raw);
    if (cwe === null) continue;
    const key = cwe.replace(/^CWE-/i, "").padStart(3, "0");
    const bucket = ratio.get(key) ?? { fit: 0, eval: 0 };
    const split = splits.get(id);
    if (split === "fit") bucket.fit += 1;
    else if (split === "eval") bucket.eval += 1;
    ratio.set(key, bucket);
  }
  for (const [cwe, bucket] of [...ratio].sort(([a], [b]) => a.localeCompare(b))) {
    const total = bucket.fit + bucket.eval;
    // §7: each class splits 3:2; a class with no eval side can never be measured.
    if (bucket.fit === 0 || bucket.eval === 0) {
      add("split_ratio", null, `CWE-${cwe} is missing a split (fit=${bucket.fit} eval=${bucket.eval})`);
    } else if (bucket.fit * 2 !== bucket.eval * 3) {
      add("split_ratio", null, `CWE-${cwe} splits ${bucket.fit}:${bucket.eval} (${total} rows), expected 3:2`);
    }
  }

  const summary: ConformanceSummary[] = RULE_ORDER.flatMap((rule) => {
    const hits = violations.filter((violation) => violation.rule === rule);
    if (hits.length === 0) return [];
    return [
      {
        rule,
        count: hits.length,
        examples: hits.slice(0, 3).map((hit) => (hit.sample === null ? hit.detail : `${hit.sample}: ${hit.detail}`)),
      },
    ];
  });

  return { ok: violations.length === 0, samples: records.size, violations, summary };
}

function formatConformance(result: ConformanceResult): string {
  const lines = [
    `conformance: ${result.ok ? "PASS" : "FAIL"} - ${result.samples} samples, ` +
      `${result.violations.length} violations across ${result.summary.length} rules`,
  ];
  for (const group of result.summary) {
    lines.push(`  ${group.rule} (${group.count})`);
    for (const example of group.examples) lines.push(`    - ${example}`);
  }
  return `${lines.join("\n")}\n`;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const positional = argv.find((value) => !value.startsWith("--"));
  const dir = resolve(positional ?? fileURLToPath(new URL("../datasets/self-built", import.meta.url)));

  if (argv.includes("--conformance")) {
    const result = await verifyConformance(dir);
    process.stdout.write(formatConformance(result));
    if (!result.ok) process.exitCode = 1;
    return;
  }

  const result = await verifyDataset(dir);
  if (result.ok) {
    process.stdout.write(`dataset ok: ${EXPECTED_SAMPLE_COUNT} samples verified at ${dir}\n`);
    return;
  }
  for (const error of result.errors) process.stderr.write(`${error}\n`);
  process.exitCode = 1;
}

if (invokedDirectly()) {
  await main();
}

