import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { DatasetManifest, SourceName } from "../src/contracts/index.js";

const CWES = ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-22", "CWE-502", "CWE-798"] as const;
type Cwe = (typeof CWES)[number];
type Risk = "low" | "medium" | "high";

const BASE_RISK: Record<Cwe, Risk> = {
  "CWE-78": "high",
  "CWE-79": "medium",
  "CWE-89": "high",
  "CWE-94": "high",
  "CWE-22": "medium",
  "CWE-502": "high",
  "CWE-798": "low",
};

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

const bump = (risk: Risk): Risk => (risk === "low" ? "medium" : "high");

const riskOf = (cwe: Cwe, changedLines: number): Risk =>
  changedLines >= 10 ? bump(BASE_RISK[cwe]) : BASE_RISK[cwe];

function lineCount(text: string): number {
  const parts = text.split("\n");
  return text.endsWith("\n") ? parts.length - 1 : parts.length;
}

function diffCount(a: string[], b: string[]): number {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      dp[i]![j] =
        a[j - 1] === b[i - 1]
          ? dp[i - 1]![j - 1]! + 1
          : Math.max(dp[i - 1]![j]!, dp[i]![j - 1]!);
    }
  }
  return n + m - 2 * dp[m]![n]!;
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

if (invokedDirectly()) {
  const dir = process.argv[2] ?? fileURLToPath(new URL("../datasets/self-built", import.meta.url));
  const result = await verifyDataset(dir);
  if (result.ok) {
    process.stdout.write(`dataset ok: ${EXPECTED_SAMPLE_COUNT} samples verified at ${dir}\n`);
  } else {
    for (const error of result.errors) {
      process.stderr.write(`${error}\n`);
    }
    process.exit(1);
  }
}
