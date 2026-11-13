/**
 * What the staged tree adds, and what the upstream file would have said on its own.
 *
 * The live drill writes three one-line importers next to every positive sample,
 * so that the file being written has a blast radius and the tier ladder puts it
 * above the boundary. That is a deliberate piece of authored context: the CRG
 * query is real, the boundary is real, and the *repository* is not - it is a
 * staged subset that this project wrote. Reporting "the tier-1 path was exercised"
 * without saying so would let a reader believe the system found a blast radius of
 * four in a real repository.
 *
 * So two numbers are measured for every staged row, with the same query:
 *
 *   - `upstream_impacted_files`: `impact` on the pinned checkout of the source
 *     repository, no authored importers, same triage bounds as the run. This says
 *     which stratum the row would have landed in had nothing been written for it.
 *   - `upstream_importers`: that count minus the file itself (the graph counts the
 *     changed file among the impacted files - the staged projection measures 4
 *     for a file with 3 importers).
 *
 * The checkout is identified by content, not by path: the file's bytes are hashed
 * as a git blob and compared with the dataset's `origin.blob_sha`. A checkout that
 * drifted reports `blob_verified: false` instead of quietly answering for another
 * revision.
 *
 * Usage:
 *   npx tsx scripts/upstream-context.ts \
 *     --dataset datasets/self-built \
 *     --config configs/b4.json \
 *     --out artifacts/staged-context.json
 *
 * The pinned checkouts are not part of the repository (juice-shop alone is 20 MB
 * of extracted tarball), so they are passed by path and the provenance of each is
 * written into the artefact next to the numbers.
 */
import { execa } from "execa";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import type { Tier } from "../src/contracts/index.js";
import { loadConfig } from "../src/config/index.js";
import { computeTier } from "../src/l2/index.js";
import { createCrgTriage } from "../src/l3/index.js";
import { synthesizeDiff } from "../src/l1/events.js";
import type { ChangeEvent } from "../src/contracts/index.js";
import {
  allSamples,
  buildIndex,
  IMPORTERS_PER_POSITIVE,
  planDrill,
  type PlannedSample,
} from "./live-drill.js";
import { arg } from "./shared.js";

/** Where the pinned checkouts live on this machine; overridable with `--repo`. */
const DEFAULT_ROOTS: Record<string, string> = {
  "juice-shop": ".tmp/latency/juice-shop",
  goof: ".tmp/latency/goof",
  dvna: ".tmp/dvna",
};

/**
 * The ceiling this measurement gives one query.
 *
 * Not `crgQueryMs`: that value decides whether the *live run* can afford the
 * query, and using it here would answer a different question - one timeout would
 * be recorded as "the file has no importers". The two are reported side by side.
 */
const UPSTREAM_QUERY_CEILING_MS = 10_000;

export interface UpstreamRow {
  sample_id: string;
  stage_group: string;
  repo: string;
  upstream_path: string;
  blob_sha: string | null;
  blob_verified: boolean;
  /** There is no upstream file to ask about: the row creates a new path. */
  upstream_applicable: boolean;
  upstream_note: string | null;
  /** Did the frozen `crgQueryMs` cover this query? A slow answer is still an answer. */
  within_budget: boolean | null;
  /** Importers this project writes into the staged tree (0 for negatives). */
  authored_importers: number;
  /** Did the row need authored context to reach its stride? */
  authored_context: boolean;
  upstream_impacted_files: number | null;
  upstream_impacted_nodes: number | null;
  upstream_importers: number | null;
  upstream_truncated: boolean | null;
  upstream_index_ready: boolean | null;
  would_be_tier: Tier | null;
  would_be_tier_source: string | null;
  ms: number | null;
}

export interface StagedContext {
  at: string;
  method: string;
  dataset_version: string;
  config: string;
  bounds: { tier0_filesMax: number; tier1_filesMax: number };
  sources: Array<{
    repo: string;
    commit: string | null;
    root: string;
    index_build_ms: number;
  }>;
  rows: UpstreamRow[];
  summary: {
    staged_rows: number;
    positives: number;
    positives_with_authored_context: number;
    /** Only the rows that have an upstream counterpart; see `not_applicable`. */
    measured_positives: number;
    positives_upstream_tier0: number;
    positives_upstream_tier_ge1: number;
    negatives_upstream_tier0: number;
    negatives_upstream_tier_ge1: number;
    not_applicable: number;
    /** Queries the frozen budget would not have covered - a timeout rate, not a detail. */
    queries_over_budget: number;
  };
  range_sentence: string;
}

/** The git blob hash of a file's bytes: the identity the dataset pins. */
export function gitBlobSha(content: Buffer): string {
  return createHash("sha1").update(`blob ${content.length}\0`).update(content).digest("hex");
}

/**
 * The upstream counterpart of the projection's query.
 *
 * Same `CrgTriage`, same bounds, same event shape; the only difference is the
 * repository it is asked about, which is the pinned source rather than the staged
 * subset.
 */
export async function measureUpstream(options: {
  root: string;
  configPath: string;
  samples: Array<{ sample: PlannedSample; repo: string; path: string; blobSha: string | null }>;
}): Promise<{ rows: UpstreamRow[]; indexBuildMs: number }> {
  const config = await loadConfig(options.configPath);
  const root = resolve(options.root);
  const indexBuildMs = await buildIndex(root);
  const triage = createCrgTriage(config, { root });
  const boundaries = { tier0: config.triage.tier0, tier1: config.triage.tier1 };
  const rows: UpstreamRow[] = [];
  for (const entry of options.samples) {
    const authoring = entry.sample.kind === "positive";
    const authored: Pick<UpstreamRow, "authored_importers" | "authored_context"> = {
      authored_importers: authoring ? IMPORTERS_PER_POSITIVE : 0,
      authored_context: authoring,
    };
    const absolute = join(root, entry.path);
    if (entry.sample.eventKind === "create" || !existsSync(absolute)) {
      // A created path has no upstream counterpart: the file does not exist in
      // the pinned revision, so there is nothing for `impact` to answer about.
      rows.push({
        sample_id: entry.sample.sampleId,
        stage_group: entry.sample.kind,
        repo: entry.repo,
        upstream_path: entry.path,
        blob_sha: entry.blobSha,
        blob_verified: false,
        upstream_applicable: false,
        upstream_note:
          entry.sample.eventKind === "create"
            ? "create event: the path does not exist upstream, so there is no unmodified blast radius"
            : `not in the pinned checkout: ${absolute}`,
        ...authored,
        upstream_impacted_files: null,
        upstream_impacted_nodes: null,
        upstream_importers: null,
        upstream_truncated: null,
        upstream_index_ready: null,
        within_budget: null,
        would_be_tier: null,
        would_be_tier_source: null,
        ms: null,
      });
      continue;
    }
    const bytes = readFileSync(absolute);
    const blobVerified = entry.blobSha !== null && gitBlobSha(bytes) === entry.blobSha;
    const event: ChangeEvent = {
      id: `upstream-${entry.sample.sampleId}`,
      sessionId: "upstream-context",
      rootCallId: "upstream-context",
      phase: "post",
      trigger: "write",
      files: [entry.path],
      diff: synthesizeDiff(entry.path, "", bytes.toString("utf8")),
      diffProvenance: "synthesized",
      ts: Date.now(),
    };
    const started = Date.now();
    // The question here is "what does the repository say", not "what can the
    // frozen budget afford" - a query that ran out of budget answers the second
    // question. So the measurement gets a ceiling of its own, and
    // `within_budget` records whether the shipped value would also have gotten
    // the answer. Collapsing the two turned one slow query into "this file has
    // no importers", which is a false statement about the repository.
    const analysis = await triage.analyze(
      event,
      started + Math.max(config.budgets.crgQueryMs, UPSTREAM_QUERY_CEILING_MS),
    );
    const ms = Date.now() - started;
    const withinBudget = ms <= config.budgets.crgQueryMs && analysis.indexReady;
    const decision = computeTier(
      {
        changedFiles: 1,
        impactedFiles: analysis.impactedFiles,
        impactedNodes: analysis.impactedNodes,
        truncated: analysis.truncated,
        unresolvedCallSites: analysis.unresolvedCallSites,
        indexReady: analysis.indexReady,
        indexStale: analysis.indexStale,
      },
      boundaries,
    );
    rows.push({
      sample_id: entry.sample.sampleId,
      stage_group: entry.sample.kind,
      repo: entry.repo,
      upstream_path: entry.path,
      blob_sha: entry.blobSha,
      blob_verified: blobVerified,
      upstream_applicable: true,
      upstream_note:
        analysis.indexReady === false
          ? "the query degraded even with a 10 s ceiling, so this row says nothing about the graph"
          : withinBudget
            ? null
            : `the frozen budget would have timed out here: ${ms} ms > crgQueryMs ${config.budgets.crgQueryMs} ms (the answer above is the repository's, not the run's)`,
      within_budget: withinBudget,
      ...authored,
      upstream_impacted_files: analysis.impactedFiles,
      upstream_impacted_nodes: analysis.impactedNodes,
      // The graph counts the written file itself among the impacted files; the
      // staged projection measures four for a file with three importers.
      upstream_importers: Math.max(0, analysis.impactedFiles - 1),
      upstream_truncated: analysis.truncated,
      upstream_index_ready: analysis.indexReady,
      would_be_tier: decision.tier,
      would_be_tier_source: decision.source,
      ms,
    });
    process.stdout.write(
      `  ${entry.sample.sampleId} ${entry.repo}:${entry.path} files=${analysis.impactedFiles} ` +
        `nodes=${analysis.impactedNodes} truncated=${analysis.truncated} ` +
        `index_ready=${analysis.indexReady} upstream_tier=${decision.tier} ${ms}ms\n`,
    );
  }
  return { rows, indexBuildMs };
}

export function summarize(rows: UpstreamRow[], stagedRows: number): StagedContext["summary"] {
  const applicable = rows.filter((row) => row.upstream_applicable);
  const positives = applicable.filter((row) => row.stage_group === "positive");
  const negatives = applicable.filter((row) => row.stage_group !== "positive");
  return {
    staged_rows: stagedRows,
    positives: rows.filter((row) => row.stage_group === "positive").length,
    positives_with_authored_context: rows.filter(
      (row) => row.stage_group === "positive" && row.authored_context,
    ).length,
    positives_upstream_tier0: positives.filter((row) => (row.would_be_tier ?? 0) === 0).length,
    positives_upstream_tier_ge1: positives.filter((row) => (row.would_be_tier ?? 0) >= 1).length,
    negatives_upstream_tier0: negatives.filter((row) => (row.would_be_tier ?? 0) === 0).length,
    negatives_upstream_tier_ge1: negatives.filter((row) => (row.would_be_tier ?? 0) >= 1).length,
    not_applicable: rows.length - applicable.length,
    measured_positives: positives.length,
    /** Queries the frozen budget would not have covered - a timeout rate, not a detail. */
    queries_over_budget: applicable.filter((row) => row.within_budget === false).length,
  };
}

export function rangeSentence(summary: StagedContext["summary"]): string {
  return (
    `tier-1 path verified on a workspace where the written file has ` +
    `${IMPORTERS_PER_POSITIVE} importers; of the ${summary.measured_positives} upstream files used, ` +
    `${summary.positives_upstream_tier0} would be tier 0 unmodified, ` +
    `${summary.positives_upstream_tier_ge1} would already be tier >= 1 ` +
    `(${summary.not_applicable} row creates a path that has no upstream counterpart)`
  );
}

function sampleFile(datasetDir: string, sampleId: string): {
  repo: string;
  file_path: string;
  origin: { blob_sha?: string | null } | null;
} {
  return JSON.parse(
    readFileSync(join(datasetDir, "samples", `${sampleId}.json`), "utf8"),
  ) as { repo: string; file_path: string; origin: { blob_sha?: string | null } | null };
}

async function main(): Promise<void> {
  const datasetDir = resolve(arg("--dataset", "datasets/self-built"));
  const configPath = resolve(arg("--config", "configs/b4.json"));
  const out = resolve(arg("--out", "artifacts/staged-context.json"));
  const roots: Record<string, string> = { ...DEFAULT_ROOTS };
  for (const pair of process.argv.slice(2).filter((a) => a.startsWith("--repo="))) {
    const [name, path] = pair.slice("--repo=".length).split("=");
    if (name === undefined || path === undefined) throw new Error(`bad --repo: ${pair}`);
    roots[name] = path;
  }
  // The triage runs the CLI with `cwd` set to this root and passes it as
  // `--repo`; a relative root would resolve against itself and the query would
  // degrade to `files = changed` without saying so.
  const declaredRoots: Record<string, string> = { ...roots };
  for (const [name, path] of Object.entries(roots)) roots[name] = resolve(path);

  const config = await loadConfig(configPath);
  const plan = planDrill(datasetDir, {});
  const samples = allSamples(plan);
  const staged = samples.filter((sample) => sample.kind !== "dep-probe");

  const byRepo = new Map<string, Array<{ sample: PlannedSample; repo: string; path: string; blobSha: string | null }>>();
  for (const sample of staged) {
    const file = sampleFile(datasetDir, sample.sampleId);
    const root = roots[file.repo];
    if (root === undefined) {
      throw new Error(`no checkout for repo ${file.repo}; pass --repo=${file.repo}=<path>`);
    }
    const list = byRepo.get(file.repo) ?? [];
    list.push({ sample, repo: file.repo, path: file.file_path, blobSha: file.origin?.blob_sha ?? null });
    byRepo.set(file.repo, list);
  }

  const provenance = JSON.parse(
    readFileSync(join(datasetDir, "source", "provenance.json"), "utf8"),
  ) as { sources?: Record<string, { commit?: string }> };
  const sources: StagedContext["sources"] = [];
  const rows: UpstreamRow[] = [];
  for (const [repo, entries] of byRepo) {
    const root = roots[repo];
    if (root === undefined) continue;
    process.stdout.write(`${repo}: ${resolve(root)}\n`);
    const measured = await measureUpstream({ root, configPath, samples: entries });
    rows.push(...measured.rows);
    sources.push({
      repo,
      commit: provenance.sources?.[repo]?.commit ?? null,
      // As handed in, not as resolved: a committed artefact should not carry one
      // machine's absolute path.
      root: declaredRoots[repo] ?? root,
      index_build_ms: measured.indexBuildMs,
    });
  }

  const summary = summarize(rows, staged.length);
  const artifact: StagedContext = {
    // Local time, like every other artefact in this repository.
    at: new Date(Date.now() + 8 * 3600_000).toISOString().replace("Z", "+08:00"),
    method:
      "`code-review-graph impact` through the same `CrgTriage.analyze` the plugin calls, on the full " +
      "pinned checkout of each source, with the triage bounds of the config named below and no authored " +
      "importers. Each file's bytes are hashed as a git blob and compared with the dataset's " +
      "`origin.blob_sha`, so the answer belongs to the pinned revision rather than to whatever tree was " +
      "on disk.",
    dataset_version: plan.datasetVersion,
    config: configPath,
    bounds: { tier0_filesMax: config.triage.tier0.filesMax, tier1_filesMax: config.triage.tier1.filesMax },
    sources,
    rows,
    summary,
    range_sentence: rangeSentence(summary),
  };
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, `${JSON.stringify(artifact, null, 2)}\n`, "utf8");
  process.stdout.write(
    `\n${summary.positives_with_authored_context}/${summary.positives} positives carry ` +
      `${IMPORTERS_PER_POSITIVE} authored importers; upstream tier 0: ` +
      `${summary.positives_upstream_tier0}/${summary.measured_positives} of the measurable positives, ` +
      `${summary.negatives_upstream_tier0}/${summary.staged_rows - summary.positives} of the negatives\n` +
      `${artifact.range_sentence}\n` +
      `wrote ${out}\n`,
  );
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/upstream-context.ts")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
