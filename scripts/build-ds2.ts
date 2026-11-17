/**
 * Reproducible builder for the self-built dataset (`ds-2`).
 *
 * The dataset is generated, not hand-edited: `source/rows.json` holds the
 * mechanical description of every row (repo, path, label, defect span, and the
 * line patch that turns the pinned upstream file into the sample's `before`
 * side), `source/provenance.json` holds the pinned commits and the supply
 * record, and this script derives everything else - `before`/`after`,
 * `changed_lines`, `risk_level`, `defect_id`, `defect_origin`, splits, hashes,
 * the manifest and its projection.
 *
 *   --emit    write `datasets/self-built`
 *   --check   emit in memory and compare, byte for byte, with the committed
 *             tree; then run the gate (`verify-dataset.ts`) on it
 *
 * `--check` needs the source clones (no network). `--emit` needs them too; the
 * gate itself (`npm run dataset:verify`) never does.
 */
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { MIN_LOW_RISK_NEGATIVES, specRiskLevel } from "./verify-dataset.js";

const SPEC_CWES = ["022", "078", "079", "089", "094", "798", "918"] as const;
const MIN_PER_CLASS = 3;
const SPLIT_TARGET = 0.6;
const SPLIT_BAND = [0.5, 0.7] as const;

interface Patch {
  at: number;
  del: number;
  ins: string[];
}

interface Row {
  id: string;
  repo: string;
  path: string;
  label: 0 | 1;
  cwe: string | null;
  defect: { start: number; end: number } | null;
  /** Positive rows only: the control re-added to the blob to build `before`. */
  patch: Patch[] | null;
  /** Negative rows only: one safe edit applied to the blob to build `after`. */
  safe_patch?: Patch[] | null;
  /**
   * Create rows only: the pinned file whose vetted text becomes the new file's
   * content. `path` is then a file that does not exist at the source commit, so
   * `before` is empty and the row exercises the create branch.
   */
  from?: string | null;
  blob_sha: string;
  language: string;
  rationale: string;
  evidence: string | null;
}

interface Provenance {
  stars_as_of: string;
  sources: Record<string, { commit: string; url: string; pedagogical: boolean; stars: number }>;
  exhaustion: Array<{
    cwe: string;
    found: number;
    required: number;
    status: string;
    sources: Array<{ repo: string; verdict: string; detail: string }>;
  }>;
  retired: { set: string; samples: number; groups: number; reason: string };
}

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

function lineCount(text: string): number {
  const parts = text.split("\n");
  return text.endsWith("\n") ? parts.length - 1 : parts.length;
}

/** `n + m - 2 * LCS`, the same measure the gate re-derives. */
function diffCount(a: string[], b: string[]): number {
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

function rebuildAfter(afterLines: string[], patch: readonly Patch[]): string {
  const out: string[] = [];
  let cursor = 0;
  for (const hunk of patch) {
    out.push(...afterLines.slice(cursor, hunk.at), ...hunk.ins);
    cursor = hunk.at + hunk.del;
  }
  out.push(...afterLines.slice(cursor));
  return out.join("\n");
}

function git(clone: string, args: string[]): string {
  return execFileSync("git", ["-C", clone, ...args], { encoding: "utf8", maxBuffer: 128 * 1024 * 1024 });
}

/** `CWE-22` and `CWE-022` are the same class; the table counts the padded key. */
function classKey(row: Row): string | null {
  return row.cwe === null ? null : row.cwe.padStart(3, "0");
}

/**
 * §10 contamination, as a category rule with no free parameter:
 *
 *   high  <=>  origin.kind = public_repo and (origin.advisory or source.pedagogical)
 *
 * Every self row is a pinned `public_repo` blob with no advisory, so the second
 * disjunct decides. All three parents are deliberately vulnerable teaching
 * apps: the vulnerable files are the reason the repository exists and have been
 * public for years, so they are in any corpus that scraped them. Star counts are
 * kept in the manifest as evidence but are not a gate - a threshold on stars is
 * a free parameter that cannot be falsified, and 14k vs 549 is a difference in
 * probability, not in kind.
 */
function contaminationRisk(source: Provenance["sources"][string]): "low" | "high" {
  return source.pedagogical ? "high" : "low";
}

function cloneOf(root: string, repo: string): string {
  for (const candidate of [join(root, repo), join(root, "p2-src", repo)]) {
    try {
      execFileSync("git", ["-C", candidate, "rev-parse", "--git-dir"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      });
      return candidate;
    } catch {
      continue;
    }
  }
  throw new Error(`no clone for ${repo} under ${root}`);
}

/**
 * Split allocation: groups are `repo:path`, a group never crosses the split,
 * and the order is a hash of the group key - not a hand-picked list, so the
 * split cannot be tuned towards whatever a probe happened to find.
 */
function allocate(rows: Row[], order: string[], groups: Map<string, Row[]>): Map<string, "fit" | "eval"> {
  const positives = rows.filter((row) => row.label === 1);
  const budget = Math.round(SPLIT_TARGET * positives.length);
  const pinned = new Set(
    [...groups].filter(([, members]) => members.some((row) => row.label === 0)).map(([key]) => key),
  );
  const size = (key: string): number => groups.get(key)!.filter((row) => row.label === 1).length;
  const out = new Map<string, "fit" | "eval">();
  let evalPositives = 0;
  for (const key of pinned) out.set(key, "eval");
  for (const key of order) {
    if (out.has(key)) continue;
    if (size(key) === 0) {
      out.set(key, "fit");
      continue;
    }
    if (evalPositives + size(key) <= budget) {
      out.set(key, "eval");
      evalPositives += size(key);
    } else {
      out.set(key, "fit");
    }
  }
  // Every class with enough rows to be reported must have at least one eval
  // group, or its recall would be unmeasurable from the start.
  for (const cwe of SPEC_CWES) {
    const inClass = positives.filter((row) => classKey(row) === cwe);
    if (inClass.length < MIN_PER_CLASS) continue;
    if (inClass.some((row) => out.get(`${row.repo}\u0000${row.path}`) === "eval")) continue;
    for (const key of order) {
      if (!groups.get(key)!.some((row) => classKey(row) === cwe)) continue;
      out.set(key, "eval");
      break;
    }
  }
  // A class with rows on only one side is measured without ever being fitted,
  // which is a different (and fixable) gap from "too few rows to fit".
  for (const cwe of SPEC_CWES) {
    const inClass = positives.filter((row) => classKey(row) === cwe);
    if (inClass.length < MIN_PER_CLASS) continue;
    if (inClass.some((row) => out.get(`${row.repo}\u0000${row.path}`) === "fit")) continue;
    for (const key of order) {
      const members = groups.get(key)!;
      if (!members.some((row) => classKey(row) === cwe)) continue;
      const others = members.filter((row) => classKey(row) === cwe);
      if (others.every((row) => out.get(key) === "fit")) continue;
      out.set(key, "fit");
      break;
    }
  }
  return out;
}

export interface Emitted {
  files: Map<string, string>;
  manifest: Record<string, unknown>;
}

export async function build(root: string, datasetDir: string): Promise<Emitted> {
  const rowsRaw = JSON.parse(await readFile(join(datasetDir, "source", "rows.json"), "utf8")) as { rows: Row[] };
  const provenance = JSON.parse(
    await readFile(join(datasetDir, "source", "provenance.json"), "utf8"),
  ) as Provenance;
  const rows = rowsRaw.rows;

  const blobs = new Map<string, string>();
  for (const row of rows) {
    const source = provenance.sources[row.repo];
    if (source === undefined) throw new Error(`${row.id}: unknown repo ${row.repo}`);
    const clone = cloneOf(root, row.repo);
    const head = git(clone, ["rev-parse", "HEAD"]).trim();
    if (head !== source.commit) {
      throw new Error(`${row.id}: ${row.repo} is at ${head}, expected the pinned ${source.commit}`);
    }
    const key = `${row.repo}\u0000${row.from ?? row.path}`;
    if (blobs.has(key)) continue;
    const text = execFileSync("git", ["-C", clone, "show", `${source.commit}:${row.from ?? row.path}`], {
      encoding: "utf8",
      maxBuffer: 128 * 1024 * 1024,
    });
    if (text.includes("\r")) throw new Error(`${row.id}: upstream blob uses CRLF`);
    const blobSha = git(clone, ["rev-parse", `${source.commit}:${row.from ?? row.path}`]).trim();
    if (blobSha !== row.blob_sha) throw new Error(`${row.id}: blob sha ${blobSha} != pinned ${row.blob_sha}`);
    blobs.set(key, text);
  }

  const groups = new Map<string, Row[]>();
  for (const row of rows) {
    const key = `${row.repo}\u0000${row.path}`;
    groups.set(key, [...(groups.get(key) ?? []), row]);
  }
  for (const [key, members] of groups) {
    const labels = new Set(members.map((row) => row.label));
    if (labels.size > 1) {
      throw new Error(`${key.replace("\u0000", ":")} hosts both a positive and a negative`);
    }
  }
  const order = [...groups.keys()].sort((a, b) => sha256(a).localeCompare(sha256(b)));
  const splitOf = allocate(rows, order, groups);

  const files = new Map<string, string>();
  const projection: Array<Record<string, unknown>> = [];
  const rootLines: string[] = [];
  const perClass = new Map<string, number>();
  const splitById = new Map<string, string>();
  const eventKinds = { edit: 0, create: 0 };
  const negativeKinds = { edit: 0, create: 0 };
  let lowRiskNegatives = 0;

  for (const row of [...rows].sort((a, b) => a.id.localeCompare(b.id))) {
    const key = `${row.repo}\u0000${row.path}`;
    const blob = blobs.get(`${row.repo}\u0000${row.from ?? row.path}`)!;
    const blobLines = blob.split("\n");
    // A positive's `after` is the pinned blob byte for byte and `before` is that
    // blob plus the re-added control. A negative's `before` is the blob and
    // `after` is the blob plus one safe edit (`safe_patch`): a whole-file
    // creation is always `high` risk, so it could never fill line 4's pool. The
    // one `from` row is the exception that exercises the create branch: its
    // `after` is the same vetted text, but `path` does not exist at the source
    // commit, so `before` is empty.
    if (row.label === 0 && (row.safe_patch ?? []).length === 0) {
      throw new Error(`${row.id}: a negative row needs a safe_patch, or before === after`);
    }
    const after = row.label === 1 ? blob : rebuildAfter(blobLines, row.safe_patch ?? []);
    const before = row.label === 1 ? rebuildAfter(blobLines, row.patch ?? []) : row.from ? "" : blob;
    const beforeLines = before.split("\n");
    const afterLines = after.split("\n");
    const changed = before === "" ? lineCount(after) : diffCount(beforeLines, afterLines);
    // Derived, never declared: the create branch is exactly "no before side".
    const eventKind = before === "" ? ("create" as const) : ("edit" as const);
    eventKinds[eventKind] += 1;
    if (row.label === 0) negativeKinds[eventKind] += 1;
    const sampleCwe = row.label === 1 ? `CWE-${row.cwe}` : null;
    const split = splitOf.get(key)!;
    splitById.set(row.id, split);
    if (row.label === 1) perClass.set(classKey(row)!, (perClass.get(classKey(row)!) ?? 0) + 1);

    const defects =
      row.label === 1
        ? [
            {
              defect_id: `${row.id}:d1`,
              cwe: sampleCwe,
              file: row.path,
              line_start: row.defect!.start,
              line_end: row.defect!.end,
              symbol: null,
              evidence: row.evidence,
            },
          ]
        : [];

    const content = sha256(`${before}\u0000${after}`);
    const risk = specRiskLevel(sampleCwe, changed);
    if (row.label === 0 && risk === "low") lowRiskNegatives += 1;
    const sample = {
      sample_id: row.id,
      schema_version: 2,
      unit: "file_write",
      language: row.language,
      sample_set: "self",
      group_id: `${row.repo}:${row.path}`,
      repo: row.repo,
      file_path: row.path,
      before,
      after,
      changed_lines: changed,
      event_kind: eventKind,
      label: row.label,
      defects,
      sample_cwe: sampleCwe,
      variant_of: null,
      rationale: row.rationale,
      expected_detectable_by: row.label === 1 ? "semgrep_only" : null,
      risk_level: risk,
      contamination_risk: contaminationRisk(provenance.sources[row.repo]!),
      defect_origin: row.label === 1 ? "real" : null,
      origin: {
        kind: "public_repo",
        ref: `${row.repo}@${provenance.sources[row.repo]!.commit}:${row.from ?? row.path}`,
        advisory: null,
        blob_sha: row.blob_sha,
        base_path: row.from ?? null,
      },
      annotator: "self",
      split,
    };
    files.set(`samples/${row.id}.json`, `${JSON.stringify(sample, null, 2)}\n`);
    rootLines.push(`${row.id}:${content}`);
    projection.push({
      sample_id: row.id,
      group_id: `${row.repo}:${row.path}`,
      split,
      cwe: sampleCwe,
      risk_level: sample.risk_level,
      paired_safe: row.label === 0,
      language: row.language,
      path: row.path,
      event_kind: eventKind,
      changed_lines: changed,
      content_sha256: content,
      expected_detectable_by: row.label === 1 ? ["semgrep"] : [],
    });
  }

  const perClassOut: Record<string, number> = {};
  const status: Record<string, string> = {};
  for (const cwe of SPEC_CWES) {
    const n = perClass.get(cwe) ?? 0;
    perClassOut[`CWE-${cwe}`] = n;
    if (n < MIN_PER_CLASS) status[`CWE-${cwe}`] = "insufficient_n";
  }
  const positives = rows.filter((row) => row.label === 1);
  const negatives = rows.filter((row) => row.label === 0);
  const evalPositives = positives.filter((row) => splitById.get(row.id) === "eval").length;
  const evalNegatives = negatives.filter((row) => splitById.get(row.id) === "eval").length;

  const manifest = {
    version: "ds-2.0.0",
    kind: "self",
    content_sha256_root: sha256(rootLines.sort().join("\n")),
    declared: {
      samples: rows.length,
      positives: positives.length,
      negatives: negatives.length,
      groups: groups.size,
      min_per_class: MIN_PER_CLASS,
      per_class: perClassOut,
      per_class_status: status,
      split: {
        fit: rows.length - evalPositives - evalNegatives,
        eval: evalPositives + evalNegatives,
        total: rows.length,
      },
      split_positives: { fit: positives.length - evalPositives, eval: evalPositives, total: positives.length },
      split_band: SPLIT_BAND,
      split_band_basis: "positives",
      split_criterion:
        "groups keyed by repo:path, ordered by sha256(group_key), greedy fill to 0.6 eval; a group never crosses the split; negatives are held out in eval so the threshold cannot be tuned against them",
      negatives_split: "eval",
      defect_origin: "real",
      defect_origin_basis:
        "a positive's vulnerable bytes on `after` are the upstream author's: `after` is byte-identical to the pinned blob (`origin.blob_sha`), so the detected defect is a real one. The project-authored side is `before` (upstream plus one re-added control); it only builds the minimal change event and `changed_lines`, and no detector ever sees it. A negative has `before` = the pinned blob and `after` = that blob plus one recorded safe edit, so `origin.blob_sha` names the base blob rather than claiming byte identity; the single `create` row carries `origin.base_path`, the pinned file its text came from. Caveat: all three sources are deliberately vulnerable teaching applications, so this is real-defect recall under a non-representative parent population, not evidence about production code.",
      negative_encoding:
        "before = pinned upstream blob; after = the same blob plus one safe edit (`safe_patch` in rows.json: empty-value guard, extracted constant, or null-coalesced binding). The diff stays under 30 lines, so a defect-free edit row is low risk and line 4 has a pool that is not defective. One row is a `create` (`from` in rows.json): its `after` is the vetted text of another negative and `before` is empty, so the create path is exercised instead of being dead code. It is 38 lines, so it is `high` risk and outside the low-risk pool; it is a behaviour sample, n=1, and no precision claim is made for it. Its write is still tier 0 (the static tier counts changed files, not lines), so semgrep and the registry review it while AOR does not.",
      event_kinds: {
        total: eventKinds,
        negatives: negativeKinds,
        basis: "derived: event_kind = create iff before === \"\"; not a declared field",
      },
      contamination_rule:
        "high iff origin.kind=public_repo and (origin.advisory or source.pedagogical); else low. Category rule, no free parameter: star counts are evidence, not a gate.",
      contamination_stars_as_of: provenance.stars_as_of,
      low_risk_negatives_required: MIN_LOW_RISK_NEGATIVES,
      low_risk_negatives: lowRiskNegatives,
      supply_exhausted: provenance.exhaustion,
    },
    retired: provenance.retired,
    sources: Object.fromEntries(
      Object.entries(provenance.sources).map(([name, source]) => [
        name,
        { commit: source.commit, url: source.url, pedagogical: source.pedagogical, stars: source.stars },
      ]),
    ),
    samples: projection,
  };
  files.set("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
  return { files, manifest };
}

/**
 * A population change must carry a version change. `version` is the only handle
 * a run directory (`eval-<version>-<ts>`) and an archived report have on the
 * sample set, so a new `content_sha256_root` under the same version makes two
 * different populations answer to one name - which is how 33, 34 and 35 samples
 * all ended up as `ds-2.0.0`.
 */
export function assertVersionTracksPopulation(
  previous: { version: string; content_sha256_root: string } | null,
  next: { version: string; content_sha256_root: string },
): void {
  if (previous === null) return;
  if (previous.version !== next.version) return;
  if (previous.content_sha256_root === next.content_sha256_root) return;
  throw new Error(
    `population changed under an unchanged manifest version (${next.version}): ` +
      `content_sha256_root ${previous.content_sha256_root} -> ${next.content_sha256_root}. ` +
      "Bump `version` in scripts/build-ds2.ts; the run directory name and every archived " +
      "report carry the version, so the population must move with it.",
  );
}

async function previousManifest(
  datasetDir: string,
): Promise<{ version: string; content_sha256_root: string } | null> {
  try {
    const raw = JSON.parse(await readFile(join(datasetDir, "manifest.json"), "utf8")) as Record<string, unknown>;
    if (typeof raw["version"] !== "string" || typeof raw["content_sha256_root"] !== "string") return null;
    return { version: raw["version"], content_sha256_root: raw["content_sha256_root"] };
  } catch {
    return null;
  }
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const datasetDir = resolve(fileURLToPath(new URL("../datasets/self-built", import.meta.url)));
  const root = resolve(argv.includes("--root") ? argv[argv.indexOf("--root") + 1]! : ".tmp");
  const emitted = await build(root, datasetDir);
  // `manifest` is written as a plain record; the version guard reads two fields
  // out of it, so narrow them here rather than casting. A manifest without them
  // is a builder bug, and failing loudly beats comparing `undefined` to a
  // string (which would silently pass the guard).
  const version = emitted.manifest["version"];
  const contentRoot = emitted.manifest["content_sha256_root"];
  if (typeof version !== "string" || typeof contentRoot !== "string") {
    throw new Error("build() produced a manifest without string version/content_sha256_root");
  }
  assertVersionTracksPopulation(await previousManifest(datasetDir), {
    version,
    content_sha256_root: contentRoot,
  });

  if (argv.includes("--emit")) {
    for (const [relative, text] of emitted.files) {
      await writeFile(join(datasetDir, relative), text, "utf8");
    }
    process.stdout.write(`emitted ${emitted.files.size} files into ${datasetDir}\n`);
    return;
  }

  const drift: string[] = [];
  for (const [relative, text] of emitted.files) {
    const target = join(datasetDir, relative);
    let actual: string | null = null;
    try {
      actual = await readFile(target, "utf8");
    } catch {
      drift.push(`missing ${relative}`);
      continue;
    }
    if (actual !== text) drift.push(`differs ${relative}`);
  }
  const declared = new Set(emitted.files.keys());
  for (const name of await readdir(join(datasetDir, "samples"))) {
    if (!declared.has(`samples/${name}`)) drift.push(`stale samples/${name}`);
  }
  if (drift.length > 0) {
    for (const line of drift) process.stderr.write(`${line}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write(`reproducible: ${emitted.files.size} files match the committed tree\n`);

  const { verifyDataset } = await import("./verify-dataset.js");
  const result = await verifyDataset(datasetDir);
  if (!result.ok) {
    for (const error of result.errors) process.stderr.write(`${error}\n`);
    process.exitCode = 1;
    return;
  }
  process.stdout.write("gate: ok\n");
}

const invokedDirectly = (): boolean => {
  const entry = process.argv[1];
  if (!entry) return false;
  return resolve(entry).toLowerCase() === fileURLToPath(import.meta.url).toLowerCase();
};

if (invokedDirectly()) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
