import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { arg, diffCount } from "./shared.js";

/**
 * Import the AACR-Bench TypeScript `Security` RIGHT subset (annotation spec #7
 * 鎼?, 鎼?1).
 *
 * The published dataset carries PR metadata and comment anchors, but not file
 * contents: `before`/`after` have to be fetched from GitHub at the PR's
 * source/target commits. Everything is therefore accounted for in
 * `import-report.json` - raw totals, LEFT drops, anchor failures, fetch
 * failures - because 鎼?1 forbids reporting only the surviving subset.
 *
 * Deliberate choices, all of them from the spec:
 * - `side=LEFT` comments are dropped (鎼?1): a deleted line has no anchor in the
 *   new file, so it cannot be matched line-wise.
 * - AACR rows have no CWE (鎼?1), so `sample_cwe` is null and `defects[].cwe` is
 *   null; they must never enter a per-CWE table.
 * - `from_line`/`to_line` are *comment* positions, not defect ranges (鎼?1). They
 *   are stored as-is and the evidence string says so, so nobody later reads a
 *   per-CWE recall out of them.
 */

const execa = promisify(execFile);

const AACR_REPO = "alibaba/aacr-bench";
const SECURITY = "Security Vulnerability";
const TS_LANGUAGES = new Set(["TypeScript"]);
const TS_EXTENSIONS = /\.(ts|tsx|mts|cts)$/i;
const CACHE = ".tmp/aacr/cache";

interface AacrComment {
  note: string;
  path: string;
  side: string;
  from_line: number;
  to_line: number;
  category: string;
  context?: string;
  is_ai_comment?: boolean;
  source_model?: string;
}

interface AacrPr {
  project_main_language: string;
  githubPrUrl: string;
  source_commit: string;
  target_commit: string;
  created_at?: string;
  merged_at?: string;
  change_line_count?: number;
  comments: AacrComment[];
}

export interface ImportReport {
  source: { repo: string; dataset: string; files: string[] };
  filters: { languages: string[]; category: string; side: string; maxBytes: number };
  counts: Record<string, number>;
  ratio: { before: string; after: string; security_stratum: string };
  drops: Array<{ reason: string; count: number; examples: string[] }>;
  samples: Array<{ sample_id: string; pr: string; path: string; label: 0 | 1; arm: string; lines: string }>;
}

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");
const repoOf = (prUrl: string): string => prUrl.replace(/^https:\/\/github\.com\//, "").replace(/\/pull\/.*$/, "");

interface FileAt {
  status: "ok" | "missing" | "too_large" | "error";
  text: string;
  detail?: string;
}

/** `gh api` is the only network path this machine allows (TLS is filtered). */
async function ghJson(path: string): Promise<unknown | null> {
  try {
    const { stdout } = await execa("gh", ["api", path], { maxBuffer: 64 * 1024 * 1024 });
    return JSON.parse(stdout);
  } catch {
    return null;
  }
}

async function fileAt(repo: string, commit: string, path: string, maxBytes: number): Promise<FileAt> {
  const cachePath = join(CACHE, repo.replace("/", "__"), commit, path.replace(/[\\/]/g, "__"));
  if (existsSync(cachePath)) return { status: "ok", text: readFileSync(cachePath, "utf8") };

  const listing = (await ghJson(`repos/${repo}/contents/${path}?ref=${commit}`)) as
    | { sha?: string; size?: number; content?: string; encoding?: string }
    | null;
  if (listing === null) return { status: "missing", text: "" };
  if ((listing.size ?? 0) > maxBytes) {
    return { status: "too_large", text: "", detail: `${listing.size} bytes` };
  }
  let text = "";
  if (typeof listing.content === "string" && listing.content.length > 0 && listing.encoding === "base64") {
    text = Buffer.from(listing.content, "base64").toString("utf8");
  } else if (typeof listing.sha === "string") {
    // Files above the contents API's inline limit come back as a bare blob sha.
    const blob = (await ghJson(`repos/${repo}/git/blobs/${listing.sha}`)) as
      | { content?: string; encoding?: string }
      | null;
    if (blob === null || typeof blob.content !== "string") return { status: "error", text: "" };
    text = Buffer.from(blob.content, "base64").toString("utf8");
  } else {
    return { status: "error", text: "" };
  }
  await mkdir(dirname(cachePath), { recursive: true });
  await writeFile(cachePath, text, "utf8");
  return { status: "ok", text };
}

const lineCount = (text: string): number => (text.length === 0 ? 0 : text.split("\n").length - (text.endsWith("\n") ? 1 : 0));

/** 鎼? derivation with `sample_cwe=null`: an unknown class is never `low`. */
const riskOf = (): "high" => "high";

interface Selected {
  pr: AacrPr;
  comment: AacrComment;
  label: 0 | 1;
  arm: "security_pos" | "security_neg" | "control";
}

function select(
  prs: AacrPr[],
  options: { category: string | null; label: 0 | 1; arm: Selected["arm"] },
  drop: (reason: string, example: string) => void,
): Selected[] {
  const out: Selected[] = [];
  for (const pr of prs) {
    if (!TS_LANGUAGES.has(pr.project_main_language)) continue;
    for (const comment of pr.comments) {
      if (options.category !== null && comment.category !== options.category) continue;
      // A comment on a Makefile can never become a TypeScript sample; filter it
      // out of every arm up front so the control arm keeps its size.
      if (!TS_EXTENSIONS.test(comment.path)) {
        drop("not_typescript_file", `${pr.githubPrUrl} ${comment.path}`);
        continue;
      }
      out.push({ pr, comment, label: options.label, arm: options.arm });
    }
  }
  return out;
}

/** Deterministic pick, so re-running the importer yields the same control arm. */
function pickDeterministic(pool: Selected[], count: number): Selected[] {
  return [...pool]
    .sort((a, b) => {
      const ha = sha256(`${a.pr.githubPrUrl}|${a.comment.path}|${a.comment.from_line}|${a.comment.note}`);
      const hb = sha256(`${b.pr.githubPrUrl}|${b.comment.path}|${b.comment.from_line}|${b.comment.note}`);
      return ha.localeCompare(hb);
    })
    .slice(0, count);
}

async function main(): Promise<void> {
  const raw = resolve(arg("--raw", ".tmp/aacr"));
  const out = resolve(arg("--out", "datasets/aacr"));
  const maxBytes = Number(arg("--max-bytes", String(512 * 1024)));

  const positivePath = join(raw, "positive_samples.json");
  const negativePath = join(raw, "negative_samples.json");
  const positives = JSON.parse(await readFile(positivePath, "utf8")) as AacrPr[];
  const negatives = JSON.parse(await readFile(negativePath, "utf8")) as AacrPr[];

  const counts: Record<string, number> = {};
  const drops: ImportReport["drops"] = [];
  const dropMap = new Map<string, string[]>();
  const drop = (reason: string, example: string): void => {
    counts[reason] = (counts[reason] ?? 0) + 1;
    const list = dropMap.get(reason) ?? [];
    if (list.length < 3) list.push(example);
    dropMap.set(reason, list);
  };

  // 鎼?1 wants the raw population before any filter, then the LEFT drop.
  const securityPos = select(positives, { category: SECURITY, label: 1, arm: "security_pos" }, drop);
  const securityNeg = select(negatives, { category: SECURITY, label: 0, arm: "security_neg" }, drop);
  counts.raw_comments_all = positives.reduce((total, pr) => total + pr.comments.length, 0);
  counts.security_ts_pos = securityPos.length;
  counts.security_ts_neg = securityNeg.length;
  const pool = [...securityPos, ...securityNeg];
  const left = pool.filter((entry) => entry.comment.side.toLowerCase() !== "right");
  for (const entry of left) drop("left_side_dropped", `${entry.pr.githubPrUrl} ${entry.comment.path}`);
  counts.pool_before_left_drop = pool.length;

  const positivesRight = securityPos.filter((entry) => entry.comment.side.toLowerCase() === "right");
  const negativesRight = securityNeg.filter((entry) => entry.comment.side.toLowerCase() === "right");

  // 鎼?: an equal-sized non-Security arm as the negative control.
  const controlPool = select(negatives, { category: null, label: 0, arm: "control" }, drop).filter(
    (entry) => entry.comment.side.toLowerCase() === "right" && entry.comment.category !== SECURITY,
  );
  const control = pickDeterministic(controlPool, positivesRight.length);

  const chosen = [...positivesRight, ...negativesRight, ...control];
  const samples: Array<Record<string, unknown>> = [];
  const manifestSamples: Array<Record<string, unknown>> = [];
  const sampleIndex: ImportReport["samples"] = [];
  let seq = 0;
  const byFile = new Map<string, { pr: AacrPr; before: string; after: string; hash: string }>();

  for (const entry of chosen) {
    const { pr, comment, label } = entry;
    const repo = repoOf(pr.githubPrUrl);
    const id = `${repo}#${comment.path}@${pr.target_commit}`;
    if (!TS_EXTENSIONS.test(comment.path)) {
      drop("not_typescript_file", `${pr.githubPrUrl} ${comment.path}`);
      continue;
    }
    let file = byFile.get(id);
    if (file === undefined) {
      const after = await fileAt(repo, pr.target_commit, comment.path, maxBytes);
      if (after.status !== "ok") {
        drop(after.status === "too_large" ? "too_large" : "fetch_failed_after", `${pr.githubPrUrl} ${comment.path} (${after.detail ?? after.status})`);
        continue;
      }
      const before = await fileAt(repo, pr.source_commit, comment.path, maxBytes);
      // A file that does not exist at the source commit is an addition: the
      // write starts from empty, which is a legitimate `before`.
      const beforeText = before.status === "ok" ? before.text : "";
      if (before.status !== "ok" && before.status !== "missing") {
        drop("fetch_failed_before", `${pr.githubPrUrl} ${comment.path} (${before.status})`);
        continue;
      }
      file = { pr, before: beforeText, after: after.text, hash: sha256(`${beforeText}\u0000${after.text}`) };
      byFile.set(id, file);
    }

    const afterLines = lineCount(file.after);
    const low = Math.min(comment.from_line, comment.to_line);
    const high = Math.max(comment.from_line, comment.to_line);
    if (!Number.isFinite(low) || low < 1 || high > afterLines) {
      drop("anchor_outside_target", `${pr.githubPrUrl} ${comment.path}:${comment.from_line}-${comment.to_line} (file has ${afterLines} lines)`);
      continue;
    }

    seq += 1;
    const sampleId = `aacr-ts-${String(seq).padStart(4, "0")}`;
    const changedLines = diffCount(
      file.before.endsWith("\n") ? file.before.slice(0, -1).split("\n") : file.before.split("\n"),
      file.after.endsWith("\n") ? file.after.slice(0, -1).split("\n") : file.after.split("\n"),
    );
    const sample = {
      sample_id: sampleId,
      schema_version: 1,
      unit: "file_write",
      language: "ts",
      sample_set: "aacr",
      group_id: `aacr:${repo}`,
      repo,
      file_path: comment.path,
      before: file.before,
      after: file.after,
      label,
      defects:
        label === 1
          ? [
              {
                defect_id: `${sampleId}#d1`,
                cwe: null,
                file: comment.path,
                line_start: low,
                line_end: high,
                symbol: null,
                evidence: `AACR comment anchor ${low}-${high} (comment position, not defect range): ${comment.note.replace(/\s+/g, " ").slice(0, 160)}`,
              },
            ]
          : [],
      sample_cwe: null,
      variant_of: null,
      expected_detectable_by: null,
      risk_level: riskOf(),
      contamination_risk: "low",
      origin: {
        kind: "aacr",
        ref: `${pr.githubPrUrl}#${comment.path}:${comment.from_line}-${comment.to_line}`,
        advisory: null,
      },
      annotator: null,
    };
    samples.push(sample);
    manifestSamples.push({
      sample_id: sampleId,
      group_id: sample.group_id,
      split: "eval",
      risk_level: sample.risk_level,
      contamination_risk: sample.contamination_risk,
      changed_lines: changedLines,
      content_sha256: sha256(`${file.before}\u0000${file.after}`),
      label,
    });
    sampleIndex.push({
      sample_id: sampleId,
      pr: pr.githubPrUrl,
      path: comment.path,
      label,
      arm: entry.arm,
      lines: `${low}-${high}`,
    });
  }

  const importedPos = samples.filter((sample) => sample["label"] === 1).length;
  const importedNeg = samples.length - importedPos;
  const importedSecurityNeg = sampleIndex.filter((entry) => entry.arm === "security_neg").length;
  counts.imported = samples.length;
  counts.imported_positive = importedPos;
  counts.imported_negative = importedNeg;
  counts.imported_security_negative = importedSecurityNeg;
  counts.imported_control_negative = sampleIndex.filter((entry) => entry.arm === "control").length;
  counts.control_arm_pool = controlPool.length;
  counts.control_arm_taken = control.length;

  for (const [reason, examples] of dropMap) drops.push({ reason, count: counts[reason] ?? 0, examples });

  const root = sha256(
    manifestSamples
      .map((sample) => `${String(sample["sample_id"])}:${String(sample["content_sha256"])}`)
      .sort()
      .join("\n"),
  );

  const manifest = {
    dataset_version: "aacr-v1-import-1",
    schema_version: 1,
    dataset: "aacr",
    source: { repo: AACR_REPO, dataset: "v1", license: "Apache-2.0" },
    split_rule: "aacr-eval-v1",
    content_sha256_root: root,
    samples: manifestSamples,
  };

  const report: ImportReport = {
    source: { repo: AACR_REPO, dataset: "v1", files: ["dataset/v1/positive_samples.json", "dataset/v1/negative_samples.json"] },
    filters: { languages: [...TS_LANGUAGES], category: SECURITY, side: "right", maxBytes },
    counts,
    ratio: {
      // 鎼?1: the raw positive:negative ratio before selection, and after.
      before: `${securityPos.length}:${securityNeg.length}`,
      after: `${importedPos}:${importedNeg}`,
      security_stratum: `${importedPos}:${importedSecurityNeg}`,
    },
    drops,
    samples: sampleIndex,
  };

  await mkdir(join(out, "samples"), { recursive: true });
  for (const sample of samples) {
    await writeFile(join(out, "samples", `${String(sample["sample_id"])}.json`), `${JSON.stringify(sample, null, 2)}\n`, "utf8");
  }
  await writeFile(join(out, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  await writeFile(join(out, "import-report.json"), `${JSON.stringify(report, null, 2)}\n`, "utf8");

  process.stdout.write(
    [
      `aacr import: ${samples.length} samples (${importedPos} positive / ${importedNeg} negative) -> ${out}`,
      `pool: security=${securityPos.length + securityNeg.length} left_dropped=${counts["left_side_dropped"] ?? 0} ` +
        `control_pool=${controlPool.length}`,
      ...drops.map((entry) => `drop ${entry.reason}: ${entry.count} (${entry.examples[0] ?? ""})`),
      "",
    ].join("\n"),
  );
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/import-aacr.ts")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
    process.exitCode = 1;
  });
}
