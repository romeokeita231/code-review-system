/**
 * Dataset gate.
 *
 * Two dataset kinds, two schemas, chosen by the manifest's `kind` - no version
 * negotiation: `ds-1` is retired and its shape is gone, so a file that still
 * looks like it fails loudly instead of being read through a compatibility
 * layer.
 *
 *   --conformance   report spec conformance as structured violations
 *   (default)       run the gate; exit 1 on any violation
 *
 * The gate is offline on purpose: it checks the committed tree against itself
 * (hashes, provenance, labels, splits) and never calls a detector or a network.
 */
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

/** §6: the seven annotated classes, padded. CWE-502 is not one of them. */
export const SPEC_CWES = ["022", "078", "079", "089", "094", "798", "918"] as const;
export type SpecCwe = (typeof SPEC_CWES)[number];

/** A class below this many rows is reported but excluded from per-class claims. */
export const MIN_PER_CLASS = 3;
/** Eval share of the positives. */
export const SPLIT_BAND = [0.5, 0.7] as const;
/** The upstream directory that must never be sampled (issue #41 ruling). */
export const CODEFIXES = "data/static/codefixes/";
/**
 * Line 4 pairs B4 against B4g on eight low-risk samples. Those pairs only mean
 * something if the samples are defect-free, so the set must carry at least this
 * many `label = 0 ∧ risk_level = low` rows; the gate fails when it does not.
 */
export const MIN_LOW_RISK_NEGATIVES = 8;

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

const str = (value: unknown): string | null => (typeof value === "string" ? value : null);
const asRecord = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};

export function lineCount(text: string): number {
  const parts = text.split("\n");
  return text.endsWith("\n") ? parts.length - 1 : parts.length;
}

export function diffCount(a: string[], b: string[]): number {
  const n = a.length;
  const m = b.length;
  let previous = new Array<number>(n + 1).fill(0);
  for (let i = 1; i <= m; i += 1) {
    const current = new Array<number>(n + 1).fill(0);
    for (let j = 1; j <= n; j += 1) {
      current[j] = a[j - 1] === b[i - 1] ? previous[j - 1]! + 1 : Math.max(previous[j]!, current[j - 1]!);
    }
    previous = current;
  }
  return n + m - 2 * previous[n]!;
}

/** 1-based inclusive window of `after` lines that differ from `before`. */
export function changedWindow(after: string, before: string): { start: number; end: number } {
  const a = after.split("\n");
  const b = before === "" ? [] : before.split("\n");
  let p = 0;
  while (p < a.length && p < b.length && a[p] === b[p]) p += 1;
  let s = 0;
  while (s < a.length - p && s < b.length - p && a[a.length - 1 - s] === b[b.length - 1 - s]) s += 1;
  return { start: p + 1, end: Math.max(p + 1, a.length - s) };
}

/**
 * §9: a defective change is `low` iff its class is 079/798 and the change is at
 * most 30 lines. A row with no defects has no class, so for ds-2 - whose
 * negatives are small safe edits - only the size applies. Imported rows keep
 * §9 strict: their `risk_level` was assigned by their importer under the older
 * rule, and re-deriving it would mean rewriting another dataset's provenance.
 */
export function specRiskLevel(
  sampleCwe: string | null,
  changedLines: number,
  options: { defectFreeIsLow?: boolean } = {},
): "low" | "high" {
  const key = sampleCwe === null ? null : sampleCwe.replace(/^CWE-/i, "").padStart(3, "0");
  if (key === null) {
    if (options.defectFreeIsLow === false) return "high";
    return changedLines <= 30 ? "low" : "high";
  }
  return (key === "079" || key === "798") && changedLines <= 30 ? "low" : "high";
}

/** §13: `{lang}-cwe{NNN}-{seq}`, or `aacr-{lang}-{seq}` for AACR rows. */
export function specSampleId(id: string, sampleSet: string): boolean {
  if (sampleSet === "aacr") return /^aacr-(ts|js|tsx|jsx)-\d{4}$/.test(id);
  return /^(ts|js|tsx|jsx)-cwe\d{3}-\d{4}$/.test(id);
}

/** `CWE-22` / `CWE-022` / `022` all normalise to `022`; null stays null. */
export function classKey(sampleCwe: string | null): SpecCwe | null {
  if (sampleCwe === null) return null;
  const digits = /CWE-(\d+)/i.exec(sampleCwe)?.[1] ?? sampleCwe;
  const padded = digits.padStart(3, "0");
  return (SPEC_CWES as readonly string[]).includes(padded) ? (padded as SpecCwe) : null;
}

/* ------------------------------------------------------------------ schema */

const Defect = z
  .object({
    defect_id: z.string().min(1),
    cwe: z.string().regex(/^CWE-\d+$/).nullable(),
    file: z.string().min(1),
    line_start: z.number().int().positive(),
    line_end: z.number().int().positive(),
    symbol: z.string().nullable(),
    evidence: z.string().min(1),
  })
  .strict();

const Shared = {
  sample_id: z.string().min(1),
  unit: z.literal("file_write"),
  language: z.enum(["ts", "js", "tsx", "jsx"]),
  group_id: z.string().min(1),
  repo: z.string().min(1),
  file_path: z.string().min(1),
  before: z.string(),
  after: z.string(),
  label: z.union([z.literal(0), z.literal(1)]),
  defects: z.array(Defect),
  sample_cwe: z.string().regex(/^CWE-\d+$/).nullable(),
  variant_of: z.string().nullable(),
  expected_detectable_by: z.enum(["both", "semgrep_only", "aor_only"]).nullable(),
  risk_level: z.enum(["low", "high"]),
  contamination_risk: z.enum(["low", "high"]),
  origin: z
    .object({
      kind: z.enum(["public_repo", "self_rewritten", "aacr", "securityeval", "cwebrench", "cwebench"]),
      ref: z.string().min(1),
      advisory: z.string().nullable(),
      blob_sha: z.string().regex(/^[0-9a-f]{40}$/).nullable().optional(),
      /** Set on a `create` row: the pinned file its text was taken from. */
      base_path: z.string().min(1).nullable().optional(),
    })
    .strict(),
  annotator: z.enum(["self", "advisor"]).nullable(),
};

/** Self-built (`ds-2`) row: every field is derived by `build-ds2.ts`. */
export const SelfSample = z
  .object({
    ...Shared,
    schema_version: z.literal(2),
    sample_set: z.literal("self"),
    changed_lines: z.number().int().nonnegative(),
    /** Derived from `before === ""`; a declared value that disagrees is a bug. */
    event_kind: z.enum(["edit", "create"]),
    rationale: z.string(),
    /** Planted by design, or observed in production code. */
    defect_origin: z.enum(["real", "injected"]).nullable(),
    split: z.enum(["fit", "eval"]),
  })
  .strict();
export type SelfSample = z.infer<typeof SelfSample>;

/** Imported AACR row: no authored control, so no rationale and no blob pin. */
export const AacrSample = z
  .object({
    ...Shared,
    schema_version: z.literal(1),
    sample_set: z.literal("aacr"),
  })
  .strict();

/* ------------------------------------------------------------- rule helpers */

/** Lines that carry no behaviour: comments and blanks. */
const COMMENT_LINE = /^\s*(\/\/|\/\*|\*|\*\/|#)/;

/**
 * D1: a diff must touch at least one line that is not a comment or blank.
 * Compared on the changed window only, so a reformat that only moves a comment
 * is still called out.
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

/** A `rationale` must name a control, not say "changed". */
export function isControlName(text: string): boolean {
  const normalized = text.trim().replace(/\s+/g, " ");
  if (normalized.length < 3) return false;
  if (NOT_A_CONTROL.test(normalized)) return false;
  return /\p{L}/u.test(normalized);
}

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

export interface VerifyResult {
  ok: boolean;
  errors: string[];
}

const RULE_ORDER = [
  "json",
  "schema",
  "kind",
  "version",
  "sample_id",
  "noop",
  "changed_lines",
  "event_kind",
  "risk_level",
  "defects",
  "defect_origin",
  "sample_cwe",
  "codefixes",
  "origin",
  "rationale",
  "contamination",
  "split",
  "split_ratio",
  "classes",
  "declared",
  "low_risk_pool",
  "manifest",
  "hash",
] as const;

const flushOrder = (violations: Violation[]): ConformanceSummary[] =>
  RULE_ORDER.flatMap((rule) => {
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

/* ------------------------------------------------------------------ checker */

interface ManifestView {
  raw: Record<string, unknown>;
  kind: "self" | "aacr";
  version: string;
  sources: Record<string, { commit: string; pedagogical: boolean; stars: number }>;
  entries: Map<string, Record<string, unknown>>;
  root: string | null;
}

function readManifest(raw: Record<string, unknown>): ManifestView {
  const kindText = str(raw["kind"]);
  const kind: "self" | "aacr" = kindText === "aacr" || raw["dataset_version"] !== undefined ? "aacr" : "self";
  const sourcesRaw = asRecord(raw["sources"]);
  const sources: Record<string, { commit: string; pedagogical: boolean; stars: number }> = {};
  for (const [name, value] of Object.entries(sourcesRaw)) {
    const source = asRecord(value);
    sources[name] = {
      commit: str(source["commit"]) ?? "",
      pedagogical: source["pedagogical"] === true,
      stars: typeof source["stars"] === "number" ? source["stars"] : 0,
    };
  }
  const entries = new Map<string, Record<string, unknown>>();
  for (const entry of Array.isArray(raw["samples"]) ? raw["samples"] : []) {
    const record = asRecord(entry);
    const id = str(record["sample_id"]);
    if (id !== null) entries.set(id, record);
  }
  return {
    raw,
    kind,
    version: str(raw["version"]) ?? str(raw["dataset_version"]) ?? "",
    sources,
    entries,
    root: str(raw["content_sha256_root"]),
  };
}

export async function verifyConformance(dir: string): Promise<ConformanceResult> {
  const violations: Violation[] = [];
  const add = (rule: string, sample: string | null, detail: string): void => {
    violations.push({ rule, sample, detail });
  };

  let raw: Record<string, unknown>;
  try {
    raw = asRecord(JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")));
  } catch (error) {
    const detail = `manifest: ${error instanceof Error ? error.message : String(error)}`;
    return { ok: false, samples: 0, violations: [{ rule: "json", sample: null, detail }], summary: [{ rule: "json", count: 1, examples: [detail] }] };
  }
  const manifest = readManifest(raw);

  const fileNames = (await readdir(join(dir, "samples"))).filter((name) => name.endsWith(".json")).sort();
  const records = new Map<string, Record<string, unknown>>();

  for (const name of fileNames) {
    let row: Record<string, unknown>;
    try {
      row = asRecord(JSON.parse(await readFile(join(dir, "samples", name), "utf8")));
    } catch (error) {
      add("json", name, error instanceof Error ? error.message : String(error));
      continue;
    }
    const id = str(row["sample_id"]) ?? name.replace(/\.json$/, "");
    records.set(id, row);
    if (name !== `${id}.json`) add("sample_id", id, `filename ${name} does not match sample_id`);

    const sampleSet = str(row["sample_set"]) ?? "self";
    if (sampleSet !== manifest.kind) {
      add("kind", id, `sample_set=${sampleSet} in a ${manifest.kind} dataset`);
    }
    if (!specSampleId(id, sampleSet)) {
      add("sample_id", id, `id ${id} does not match the §13 pattern for sample_set=${sampleSet}`);
    }

    const schema = sampleSet === "aacr" ? AacrSample.safeParse(row) : SelfSample.safeParse(row);
    if (!schema.success) {
      const unknown = schema.error.issues.find((issue) => issue.code === "unrecognized_keys");
      if (unknown !== undefined) {
        const keys = (unknown as { keys?: string[] }).keys ?? [];
        add("schema", id, `unrecognized keys: ${keys.join(", ")}`);
      }
      const rest = schema.error.issues.filter((issue) => issue.code !== "unrecognized_keys");
      for (const issue of rest.slice(0, 3)) {
        const where = issue.path.length > 0 ? `${issue.path.join(".")}: ` : "";
        add("schema", id, `${where}${issue.message}`);
      }
      if (rest.length > 3) add("schema", id, `(+${rest.length - 3} more schema issues)`);
    }

    const expectedVersion = sampleSet === "aacr" ? 1 : 2;
    if (row["schema_version"] !== expectedVersion) {
      add("version", id, `schema_version=${String(row["schema_version"])} != ${expectedVersion}`);
    }

    const before = str(row["before"]) ?? "";
    const after = str(row["after"]) ?? "";
    if (sha256(before) === sha256(after)) {
      add("noop", id, "before === after: a no-op write is not a sample");
    } else if (!substantiveChange(before, after)) {
      add("noop", id, "diff touches only comments/blank lines");
    }

    const defects = Array.isArray(row["defects"]) ? row["defects"].map(asRecord) : [];
    const populated = defects.length > 0;
    const sampleCwe = str(row["sample_cwe"]);
    const label = row["label"];
    // A positive's `before` is authored, so the diff measures the change event.
    // A negative's `before` is the pinned blob and `after` is that blob plus one
    // safe edit; only `before === ""` (no such row here) falls back to the whole
    // file.
    const changedLines =
      before === ""
        ? lineCount(after)
        : diffCount(before.split("\n"), after.split("\n"));
    if (sampleSet === "self" && typeof row["changed_lines"] === "number" && row["changed_lines"] !== changedLines) {
      add("changed_lines", id, `${String(row["changed_lines"])} != derived ${changedLines}`);
    }
    // `event_kind` is derived, so the only thing to check is that the declared
    // value is the derivation. A dataset that declares `create` on an edit row
    // would let a report claim create coverage it never measured.
    if (sampleSet === "self") {
      const derivedKind = before === "" ? "create" : "edit";
      if (row["event_kind"] !== derivedKind) {
        add("event_kind", id, `${String(row["event_kind"])} != derived ${derivedKind}`);
      }
      const basePath = asRecord(row["origin"])["base_path"];
      if (derivedKind === "create") {
        if (typeof basePath !== "string" || basePath.length === 0) {
          add("event_kind", id, "create row does not name the pinned file it was taken from");
        }
      } else if (basePath !== null && basePath !== undefined) {
        add("event_kind", id, "edit row carries origin.base_path");
      }
    }

    if ((label === 1) !== populated) {
      add("defects", id, `label ${String(label)} disagrees with defects (${defects.length})`);
    }

    // Ruling: `sample_cwe` is non-null exactly when the row carries defects.
    if (sampleSet === "self" && populated !== (sampleCwe !== null)) {
      add("sample_cwe", id, populated ? "row has defects but sample_cwe=null" : "row has no defects but carries sample_cwe");
    }
    if (sampleCwe !== null && classKey(sampleCwe) === null) {
      add("classes", id, `${sampleCwe} is not one of the §6 classes`);
    }

    const declaredRisk = str(row["risk_level"]);
    const derivedRisk = specRiskLevel(sampleCwe, changedLines, {
      defectFreeIsLow: sampleSet === "self",
    });
    if (declaredRisk !== null && declaredRisk !== derivedRisk) {
      add("risk_level", id, `${declaredRisk} != §9 derivation ${derivedRisk}`);
    }

    const origin = asRecord(row["origin"]);
    const originRef = str(origin["ref"]) ?? "";
    // Ruling: the codefixes tree is not a sample source, at any offset.
    if (originRef.includes(CODEFIXES) || str(row["file_path"])?.includes(CODEFIXES) === true) {
      add("codefixes", id, `origin.ref points into ${CODEFIXES}, which is permanently excluded`);
    }

    if (sampleSet === "self") {
      const repo = str(row["repo"]) ?? "";
      const source = manifest.sources[repo];
      if (source === undefined) {
        add("origin", id, `repo ${repo} is not declared in manifest.sources`);
      } else {
        const basePath = str(origin["base_path"]) ?? str(row["file_path"]) ?? "";
        const expectedRef = `${repo}@${source.commit}:${basePath}`;
        if (originRef !== expectedRef) add("origin", id, `origin.ref ${originRef} != ${expectedRef}`);
        const blobSha = str(origin["blob_sha"]);
        if (blobSha === null) add("origin", id, "self row is missing origin.blob_sha");
        else if (blobSha.length !== 40) add("origin", id, `origin.blob_sha ${blobSha} is not a git blob id`);
      }
      if (origin["kind"] !== "public_repo") {
        add("origin", id, `origin.kind ${String(origin["kind"])} != public_repo`);
      }

      // Ruling: `defect_origin` is non-null exactly when the row has defects.
      // It follows the *bytes*, not the source's intent: `after` is the pinned
      // upstream blob byte for byte, so a self positive is a `real` defect and
      // the project only authored the `before` side.
      const defectOrigin = row["defect_origin"] ?? null;
      if (populated !== (defectOrigin !== null)) {
        add(
          "defect_origin",
          id,
          populated ? "row has defects but defect_origin=null" : "row has no defects but carries defect_origin",
        );
      }
      if (defectOrigin !== null) {
        const pinned = origin["kind"] === "public_repo" && str(origin["blob_sha"]) !== null;
        if (defectOrigin !== "real" || !pinned) {
          add(
            "defect_origin",
            id,
            `${String(defectOrigin)} != real for a row whose after is a pinned upstream blob`,
          );
        }
      }

      // Ruling: `rationale` is required on every self row (positive included),
      // because the positive row's `before` is the side we authored.
      const rationale = str(row["rationale"]);
      if (rationale === null || rationale.trim().length === 0) {
        add("rationale", id, "self row is missing `rationale`");
      } else if (!isControlName(rationale)) {
        add("rationale", id, `rationale "${rationale}" names no control`);
      }

      if (populated && row["expected_detectable_by"] === null) {
        add("defects", id, "positive row has no expected_detectable_by");
      }
      if (!populated && row["expected_detectable_by"] !== null) {
        add("defects", id, "negative row declares expected_detectable_by");
      }
    }

    // §10: contamination is derived, not filled. `high` iff the row is public
    // and either carries an advisory, or comes from a pedagogical source -
    // a category rule with no free parameter. Star counts stay in the manifest
    // as evidence of how popular the parent is, not as a gate.
    const declaredContamination = str(row["contamination_risk"]);
    const advisory = str(origin["advisory"]) !== null;
    const declaredSource = manifest.sources[str(row["repo"]) ?? ""];
    const expectedContamination =
      origin["kind"] === "public_repo" && (advisory || declaredSource?.pedagogical === true)
        ? "high"
        : "low";
    if (declaredContamination !== null && declaredContamination !== expectedContamination) {
      add(
        "contamination",
        id,
        `contamination_risk ${declaredContamination} != §10 derivation ${expectedContamination}`,
      );
    }

    // Defect spans: derived id, ascending by first changed line, tight span.
    const afterLines = after.split("\n").length;
    const window = changedWindow(after, before);
    const sorted = [...defects].sort((a, b) => Number(a["line_start"] ?? 0) - Number(b["line_start"] ?? 0));
    for (const defect of sorted) {
      const index = sorted.indexOf(defect) + 1;
      const expectedId = sampleSet === "aacr" ? `${id}#d${index}` : `${id}:d${index}`;
      const defectId = str(defect["defect_id"]) ?? "";
      if (defectId !== expectedId) add("defects", id, `defect_id ${defectId || "(missing)"} should be ${expectedId}`);
      if (defect["file"] !== row["file_path"]) add("defects", id, `defect ${defectId} file != file_path`);
      const start = typeof defect["line_start"] === "number" ? defect["line_start"] : null;
      const end = typeof defect["line_end"] === "number" ? defect["line_end"] : null;
      if (start === null || end === null || end < start) {
        add("defects", id, `defect ${defectId} has an unusable span`);
        continue;
      }
      if (sampleSet === "self" && end - start + 1 > 3) {
        add("defects", id, `defect ${defectId} spans ${end - start + 1} lines (> 3)`);
      }
      if (start < 1 || end > afterLines) add("defects", id, `defect ${defectId} span ${start}-${end} outside after bounds`);
      if (sampleSet === "self" && populated && (start < window.start || end > window.end)) {
        add("defects", id, `defect ${defectId} span ${start}-${end} is outside the changed window ${window.start}-${window.end}`);
      }
      if (sampleSet === "self" && defect["cwe"] !== sampleCwe) add("defects", id, `defect ${defectId} cwe != sample_cwe`);
    }
  }

  // `variant_of` chains: same file, same class, same split, one of them labeled.
  for (const [id, row] of records) {
    const variant = str(row["variant_of"]);
    if (variant === null) continue;
    const main = records.get(variant);
    if (main === undefined) {
      add("defects", id, `variant_of ${variant} does not exist`);
      continue;
    }
    if (str(main["file_path"]) !== str(row["file_path"])) add("defects", id, `variant_of ${variant} sits on another file`);
    if (str(main["sample_cwe"]) !== str(row["sample_cwe"])) add("defects", id, `variant_of ${variant} has another class`);
  }

  const selfRows = [...records].filter(([, row]) => (str(row["sample_set"]) ?? "self") === "self");
  if (manifest.kind === "self") {
    if (!manifest.version.startsWith("ds-2")) {
      add("version", null, `self-built manifest version "${manifest.version}" is not ds-2`);
    }
    checkSplit(records, selfRows, manifest, add);
    checkDeclared(manifest, selfRows, add);
  }

  if (manifest.kind === "self") checkHashes(records, manifest, add);

  const summary = flushOrder(violations);
  return { ok: violations.length === 0, samples: records.size, violations, summary };
}

function checkSplit(
  records: Map<string, Record<string, unknown>>,
  selfRows: Array<[string, Record<string, unknown>]>,
  manifest: ManifestView,
  add: (rule: string, sample: string | null, detail: string) => void,
): void {
  const groups = new Map<string, Set<string>>();
  const perClass = new Map<SpecCwe, { fit: number; eval: number }>();
  let evalPositives = 0;
  let totalPositives = 0;

  for (const [id, row] of selfRows) {
    const split = str(row["split"]);
    if (split !== "fit" && split !== "eval") {
      add("split", id, `split ${String(split)} is not fit|eval`);
      continue;
    }
    if (manifest.entries.get(id)?.["split"] !== split) {
      add("split", id, `sample split ${split} != manifest split ${String(manifest.entries.get(id)?.["split"])}`);
    }
    const key = `${str(row["repo"])}\u0000${str(row["file_path"])}`;
    groups.set(key, (groups.get(key) ?? new Set()).add(split));
    const cwe = classKey(str(row["sample_cwe"]));
    if (cwe !== null) {
      const bucket = perClass.get(cwe) ?? { fit: 0, eval: 0 };
      bucket[split] += 1;
      perClass.set(cwe, bucket);
      totalPositives += 1;
      if (split === "eval") evalPositives += 1;
    } else if (split !== "eval") {
      add("split", id, "a negative row must sit in eval (the threshold must not see it)");
    }
  }

  for (const [key, splits] of groups) {
    if (splits.size > 1) {
      add("split", null, `group ${key.replace("\u0000", ":")} crosses the split (${[...splits].join("/")})`);
    }
  }

  // A file that already hosts a positive cannot host a negative: the positive's
  // `before` is that file plus a control, so the two rows are near-duplicates,
  // and across a split the pair leaks the other side's label.
  const fileOf = (row: Record<string, unknown>): string =>
    `${str(row["repo"])}\u0000${str(row["file_path"])}`;
  const positivesByFile = new Map<string, string>();
  for (const [id, row] of selfRows) {
    if (classKey(str(row["sample_cwe"])) !== null) positivesByFile.set(fileOf(row), id);
  }
  for (const [id, row] of selfRows) {
    if (classKey(str(row["sample_cwe"])) !== null) continue;
    const host = positivesByFile.get(fileOf(row));
    if (host !== undefined) {
      add("split", id, `negative shares a file with positive ${host}`);
    }
  }

  for (const cwe of SPEC_CWES) {
    const bucket = perClass.get(cwe);
    if (bucket === undefined) {
      add("classes", null, `§6 class CWE-${cwe} has no samples`);
      continue;
    }
    const total = bucket.fit + bucket.eval;
    if (total >= MIN_PER_CLASS && (bucket.fit === 0 || bucket.eval === 0)) {
      add("split_ratio", null, `CWE-${cwe} has ${total} rows but only one side (fit=${bucket.fit} eval=${bucket.eval})`);
    }
  }

  if (totalPositives > 0) {
    const share = evalPositives / totalPositives;
    if (share < SPLIT_BAND[0] || share > SPLIT_BAND[1]) {
      add("split_ratio", null, `eval share ${share.toFixed(3)} (${evalPositives}/${totalPositives}) is outside ${SPLIT_BAND.join("-")}`);
    }
  }
  void records;
}

function checkDeclared(
  manifest: ManifestView,
  selfRows: Array<[string, Record<string, unknown>]>,
  add: (rule: string, sample: string | null, detail: string) => void,
): void {
  const declared = asRecord(manifest.raw["declared"]);
  const perClass = new Map<string, number>();
  const perClassStatus: Record<string, string> = {};
  let positives = 0;
  let negatives = 0;
  let lowRiskNegatives = 0;
  const eventKinds = { edit: 0, create: 0 };
  const negativeKinds = { edit: 0, create: 0 };
  const groups = new Set<string>();
  const splitCount = { fit: 0, eval: 0 };
  const splitPositives = { fit: 0, eval: 0 };

  for (const [, row] of selfRows) {
    const cwe = classKey(str(row["sample_cwe"]));
    const label = row["label"];
    const split = str(row["split"]);
    groups.add(`${str(row["repo"])}\u0000${str(row["file_path"])}`);
    if (split === "fit" || split === "eval") splitCount[split] += 1;
    // Derived here as well, so `declared.event_kinds` is a check on the tree
    // rather than a copy of it.
    const rowKind = str(row["before"]) === "" ? "create" : "edit";
    eventKinds[rowKind] += 1;
    if (label === 1) {
      positives += 1;
      if (cwe !== null) perClass.set(cwe, (perClass.get(cwe) ?? 0) + 1);
      if (split === "fit" || split === "eval") splitPositives[split] += 1;
    } else {
      negatives += 1;
      negativeKinds[rowKind] += 1;
      // Derive the pool from the diff, not from the declared field: a row that
      // declares `low` while its diff covers the whole file is exactly the
      // silent inflation this assertion exists to stop.
      const before = str(row["before"]) ?? "";
      const after = str(row["after"]) ?? "";
      const changed = before === "" ? lineCount(after) : diffCount(before.split("\n"), after.split("\n"));
      if (specRiskLevel(null, changed) === "low") lowRiskNegatives += 1;
    }
  }
  for (const cwe of SPEC_CWES) {
    if ((perClass.get(cwe) ?? 0) < MIN_PER_CLASS) perClassStatus[`CWE-${cwe}`] = "insufficient_n";
  }

  const expect = (field: string, actual: unknown, expected: unknown): void => {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      add("declared", null, `declared.${field} ${JSON.stringify(actual)} != derived ${JSON.stringify(expected)}`);
    }
  };
  expect("samples", declared["samples"], selfRows.length);
  expect("positives", declared["positives"], positives);
  expect("negatives", declared["negatives"], negatives);
  expect("groups", declared["groups"], groups.size);
  expect("per_class", declared["per_class"], Object.fromEntries(SPEC_CWES.map((cwe) => [`CWE-${cwe}`, perClass.get(cwe) ?? 0])));
  expect("per_class_status", declared["per_class_status"], perClassStatus);
  expect("split", declared["split"], { fit: splitCount.fit, eval: splitCount.eval, total: selfRows.length });
  expect("split_positives", declared["split_positives"], { ...splitPositives, total: positives });
  expect("split_band", declared["split_band"], [...SPLIT_BAND]);
  expect("min_per_class", declared["min_per_class"], MIN_PER_CLASS);
  expect("low_risk_negatives", declared["low_risk_negatives"], lowRiskNegatives);
  expect("low_risk_negatives_required", declared["low_risk_negatives_required"], MIN_LOW_RISK_NEGATIVES);
  const declaredKinds = asRecord(declared["event_kinds"]);
  expect("event_kinds.total", declaredKinds["total"], eventKinds);
  expect("event_kinds.negatives", declaredKinds["negatives"], negativeKinds);

  // Ruling: the pool may not be a single event type. A defect-free denominator
  // made only of edits says nothing about a create, and a create-only pool
  // cannot pair B4/B4g on an existing file.
  if (negativeKinds.edit === 0) {
    add("event_kind", null, "no `edit` negative staged: the precision denominator only covers creates");
  }
  if (negativeKinds.create === 0) {
    add("event_kind", null, "no `create` negative staged: the create branch is untested by construction");
  }

  // Line 4 pairs B4/B4g on eight low-risk samples; if the pool is not
  // defect-free the pairs measure a different population than line 1's
  // precision denominator, and the acceptance line silently becomes easier.
  if (lowRiskNegatives < MIN_LOW_RISK_NEGATIVES) {
    add(
      "low_risk_pool",
      null,
      `${lowRiskNegatives} defect-free low-risk rows; line 4 needs ${MIN_LOW_RISK_NEGATIVES}`,
    );
  }

  // Ruling: a class below the threshold must carry a supply record, not just
  // a status - "insufficient_n" alone cannot tell a reader whether the source
  // ran dry or nobody looked.
  const exhaustion = Array.isArray(declared["supply_exhausted"]) ? declared["supply_exhausted"].map(asRecord) : [];
  for (const cwe of SPEC_CWES) {
    if ((perClass.get(cwe) ?? 0) >= MIN_PER_CLASS) continue;
    const record = exhaustion.find((entry) => str(entry["cwe"])?.padStart(3, "0") === cwe);
    if (record === undefined) {
      add("declared", null, `CWE-${cwe} is insufficient_n without a supply record`);
      continue;
    }
    if (record["found"] !== (perClass.get(cwe) ?? 0)) {
      add("declared", null, `supply record for CWE-${cwe} says found=${String(record["found"])}, tree has ${perClass.get(cwe) ?? 0}`);
    }
    const sources = Array.isArray(record["sources"]) ? record["sources"].map(asRecord) : [];
    if (sources.length < 3) {
      add("declared", null, `supply record for CWE-${cwe} names ${sources.length} sources, expected every searched source`);
    }
    for (const source of sources) {
      if (str(source["verdict"]) === null || str(source["detail"]) === null) {
        add("declared", null, `supply record for CWE-${cwe} has a source without verdict/detail`);
      }
    }
  }
}

function checkHashes(
  records: Map<string, Record<string, unknown>>,
  manifest: ManifestView,
  add: (rule: string, sample: string | null, detail: string) => void,
): void {
  const rootLines: string[] = [];
  for (const [id, row] of records) {
    const before = str(row["before"]) ?? "";
    const after = str(row["after"]) ?? "";
    const content = sha256(`${before}\u0000${after}`);
    rootLines.push(`${id}:${content}`);
    const entry = manifest.entries.get(id);
    if (entry === undefined) {
      add("manifest", id, "sample file is not listed in the manifest");
      continue;
    }
    if (str(entry["content_sha256"]) !== content) {
      add("hash", id, `content hash mismatch: manifest ${String(entry["content_sha256"])} != actual ${content}`);
    }
    const pairs: Array<[string, unknown, unknown]> = [
      ["group_id", row["group_id"], entry["group_id"]],
      ["split", row["split"], entry["split"]],
      ["cwe", row["sample_cwe"], entry["cwe"]],
      ["risk_level", row["risk_level"], entry["risk_level"]],
      ["paired_safe", row["label"] === 0, entry["paired_safe"]],
      ["language", row["language"], entry["language"]],
      ["path", row["file_path"], entry["path"]],
      ["changed_lines", row["changed_lines"], entry["changed_lines"]],
      ["expected_detectable_by", row["label"] === 1 ? ["semgrep"] : [], entry["expected_detectable_by"]],
    ];
    for (const [field, actual, listed] of pairs) {
      if (JSON.stringify(actual) !== JSON.stringify(listed)) {
        add("manifest", id, `manifest/file mismatch: ${field}`);
      }
    }
  }
  for (const id of manifest.entries.keys()) {
    if (!records.has(id)) add("manifest", id, "manifest lists a sample with no file");
  }
  const root = sha256(rootLines.sort().join("\n"));
  if (manifest.root !== null && manifest.root !== root) {
    add("hash", null, `root hash drift: manifest ${manifest.root} != actual ${root}`);
  }
}

/** Gate entry point: the same rule set, flattened into errors. */
export async function verifyDataset(dir: string): Promise<VerifyResult> {
  const result = await verifyConformance(dir);
  const errors = result.violations.map(
    (violation) => `${violation.rule}: ${violation.sample === null ? "-" : violation.sample}: ${violation.detail}`,
  );
  return { ok: result.ok, errors };
}

/* --------------------------------------------------------------------- cli */

export function formatConformance(result: ConformanceResult): string {
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

const invokedDirectly = (): boolean => {
  const entry = process.argv[1];
  if (!entry) return false;
  return resolve(entry).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
};

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
  if (!result.ok) {
    for (const error of result.errors) process.stderr.write(`${error}\n`);
    process.exitCode = 1;
    return;
  }
  const raw = asRecord(JSON.parse(await readFile(join(dir, "manifest.json"), "utf8")));
  const declared = asRecord(raw["declared"]);
  process.stdout.write(
    `dataset ok: ${String(declared["samples"])} samples ` +
      `(${String(declared["positives"])} positive / ${String(declared["negatives"])} negative), ` +
      `${String(declared["groups"])} groups, version ${str(raw["version"]) ?? "?"}\n`,
  );
  const perClass = asRecord(declared["per_class"]);
  const rows = SPEC_CWES.map((cwe) => {
    const status = asRecord(declared["per_class_status"])[`CWE-${cwe}`];
    return `  CWE-${cwe}: ${String(perClass[`CWE-${cwe}`] ?? 0)}${status === undefined ? "" : ` (${String(status)})`}`;
  });
  process.stdout.write(`${rows.join("\n")}\n`);
}

if (invokedDirectly()) {
  await main();
}
