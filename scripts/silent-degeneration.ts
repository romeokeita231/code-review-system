/**
 * The silent-degeneration checks. Each one is named after a judgement that
 * looked right and was wrong, taken from the implementation and research
 * sessions that produced #43 / #45-#48 / #50 / #51.
 *
 * They share a shape: none of these failures throw. The code runs, the report
 * renders, the number is printed, and the number is about something else. That
 * is why each check asserts a *structural* fact rather than a value - a group
 * that cannot span two baselines, a field name that must exist, a source label
 * that must not be `unknown`.
 *
 * `scripts/gate-replay.ts` feeds each check the incident's own inputs and
 * requires it to go red. A check that stops catching its incident fails there.
 */
import { existsSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { line3PairKey } from "./acceptance.js";
import { capture } from "./capture.js";
import type { GateVerdict } from "./shared.js";

export interface RowLike {
  baseline?: unknown;
  sample?: unknown;
}

/**
 * #43 (1) and (2): "the 26/4/10 line-3 reading is agent behaviour".
 *
 * `perSample` keyed on the sample name alone, and B4 and B4g stage *the same
 * sample names*. Two independent runs were merged into one timeline, so B4g's
 * staged write counted as a later write of B4 and B4g's terminal warning turned
 * B4's edits into "unfixed". Re-keying to `${baseline}\0${sample}` moved
 * `recurred` 4 -> 1 and changed the whole composition of `unfixed`.
 *
 * The invariant is the fix, stated once: a group is one run of one sample. No
 * group may hold rows from two baselines. The key function is a parameter so the
 * replay can pass the *old* keying and watch it fail.
 */
export function judgePairGrouping(
  rows: readonly RowLike[],
  keyOf: (row: RowLike) => string = (row) =>
    line3PairKey(String(row.baseline ?? ""), String(row.sample ?? "")),
): GateVerdict {
  const groups = new Map<string, Set<string>>();
  for (const row of rows) {
    const key = keyOf(row);
    const baselines = groups.get(key) ?? new Set<string>();
    baselines.add(String(row.baseline ?? ""));
    groups.set(key, baselines);
  }
  const mixed = [...groups.entries()].filter(([, baselines]) => baselines.size > 1);
  return {
    name: "line 3 groups one run of one sample",
    ok: mixed.length === 0,
    detail:
      mixed.length === 0
        ? `${groups.size} group(s) over ${rows.length} row(s), every group single-baseline`
        : `${mixed.length} group(s) merge baselines: ` +
          mixed
            .slice(0, 5)
            .map(([key, baselines]) => `"${key.replace(/[\u0000]/g, "|")}" <- ${[...baselines].join("+")}`)
            .join(", ") +
          `. B4 and B4g are independent runs that write the same sample names; pooling them by ` +
          `name lets one baseline's write answer for the other, and it reads as agent behaviour`,
  };
}

/**
 * #43 (7) and #51 (4): "running acceptance.ts bare is the same as
 * `--stage evaluate`".
 *
 * It is not: the bare CLI leaves `rowsSource="unknown"`, line 4 degrades, and the
 * output stops being comparable with the run it is supposed to describe. The
 * failure is quiet - the report still renders, with `source=unknown` where
 * `source=live` should be.
 */
export function judgeRowsSource(input: {
  rowsSource: string;
  /** A sibling `run.json` means this directory *is* a run, not a scratch corpus. */
  runJsonPresent: boolean;
  /** The rendered artefact, when there is one, to catch a published `source=unknown`. */
  renderedText?: string | null;
}): GateVerdict {
  const publishedUnknown =
    input.renderedText !== null &&
    input.renderedText !== undefined &&
    /source=unknown/.test(input.renderedText);
  const bad = publishedUnknown || (input.rowsSource === "unknown" && input.runJsonPresent);
  return {
    name: "line 4 knows where its rows came from",
    ok: !bad,
    detail: bad
      ? publishedUnknown
        ? `a published artefact says \`source=unknown\`: line 4's ratio was computed without the ` +
          `run context that makes it comparable, and it reads like a measurement anyway`
        : `the evaluator ran on a directory that holds a run.json, with rowsSource="unknown": ` +
          `the bare CLI does not carry live context, so line 4 degrades to \`source=unknown\` and ` +
          `its ratios stop being comparable with the run they describe. Use ` +
          `\`drill --stage evaluate --out <run dir>\``
      : `rowsSource=${input.rowsSource}, run.json ${input.runJsonPresent ? "present" : "absent"}`,
  };
}

export interface SampleDefect {
  id: string;
  defects: ReadonlyArray<Record<string, unknown>>;
}

/**
 * #45-#48: "the field is `defects[].lines`".
 *
 * It is `line_start` / `line_end`. Reading the wrong key did not throw: every
 * row came back `in_defect: false`, which is a number that means "the model
 * never wrote inside a defect" and was in fact "the parser found nothing".
 *
 * Two assertions, both cheap: a defect carries numeric `line_start` / `line_end`,
 * and it does not carry a `lines` key. The second is the specific wrong shape;
 * the first catches the next one.
 */
export function judgeDefectSpans(samples: readonly SampleDefect[]): GateVerdict {
  const broken: string[] = [];
  let total = 0;
  for (const sample of samples) {
    for (const defect of sample.defects) {
      total += 1;
      const hasSpan =
        typeof defect["line_start"] === "number" && typeof defect["line_end"] === "number";
      const hasWrongShape = "lines" in defect;
      if (!hasSpan || hasWrongShape) {
        broken.push(
          `${sample.id}: ${hasWrongShape ? "carries `lines`" : "no numeric line_start/line_end"} ` +
            `(keys ${Object.keys(defect).join(",")})`,
        );
      }
    }
  }
  return {
    name: "dataset defects carry line_start/line_end",
    ok: broken.length === 0,
    detail:
      broken.length === 0
        ? `${samples.length} sample(s), ${total} defect(s), every one with a numeric span`
        : `${broken.length}/${total} defect(s) cannot be located: ${broken.slice(0, 5).join("; ")}. ` +
          `A misread field does not throw - it makes every row \`in_defect: false\`, which is a ` +
          `statement about the model that is really a statement about the parser`,
  };
}

/**
 * "A capped pass is a prefix, not a result" (2026-11-18).
 *
 * When any pass hit its wall-clock cap the rows are the first part of a run.
 * Publishing `N/5` from that is publishing a score for a measurement that never
 * finished.
 */
export function judgeTruncatedRun(input: {
  truncated: boolean;
  gateScorePublished: boolean;
}): GateVerdict {
  const bad = input.truncated && input.gateScorePublished;
  return {
    name: "a truncated run publishes no score",
    ok: !bad,
    detail: bad
      ? `the manifest says truncated=true and a gate score was published anyway: the rows are a ` +
        `prefix, so the score describes the part of the run that fit, not the run`
      : input.truncated
        ? "truncated=true, no score published"
        : "not truncated",
  };
}

/** Everything that must start with `node` to be runnable in the default sandbox. */
const NEEDS_SPAWNING_TRANSPILER = /^(tsx|vitest|esbuild|vite|ts-node)\b|(^|\s)npx\s+(tsx|vitest)\b/;

/**
 * Friction ③: "the replacement check does not start".
 *
 * `wiring:check` was written as the honest alternative to
 * `--allow-degraded`, and it exited 1 with `spawn EPERM` from esbuild in the
 * default sandbox. The rule this asserts is the fix, not a preference: an
 * entry point named after a gate must be startable without a spawning
 * transpiler, or it is a gate that reports on the environment instead of the
 * repository.
 */
export function judgeGateEntrypoints(scripts: Readonly<Record<string, string>>): GateVerdict[] {
  const gated = Object.entries(scripts).filter(([name]) => /^(gate|wiring):/.test(name));
  const offenders = gated.filter(([, command]) => NEEDS_SPAWNING_TRANSPILER.test(command));
  const skipped = Object.entries(scripts)
    .filter(([name, command]) => !/^(gate|wiring):/.test(name) && NEEDS_SPAWNING_TRANSPILER.test(command))
    .map(([name]) => name);
  const verdicts: GateVerdict[] = [
    {
      name: "gate entrypoints start without a transpiler",
      ok: offenders.length === 0,
      detail:
        offenders.length === 0
          ? `${gated.length} gate script(s), all started by \`node\``
          : offenders
              .map(([name, command]) => `${name} -> ${command}`)
              .join("; ") +
            `: esbuild's service worker needs an IPC pipe that the default sandbox refuses ` +
            `(spawn EPERM), so these exit 1 with a stack trace that says nothing about the repo`,
    },
  ];
  if (skipped.length > 0) {
    // Not a failure: `npm test` and the tsx-based tooling are for a non-sandbox
    // shell. Recorded so the gap is visible instead of being discovered again.
    verdicts.push({
      name: "scripts that still need a non-sandbox shell",
      ok: true,
      na: true,
      detail: `na: ${skipped.length} script(s) still start through tsx/vitest and cannot run in the default sandbox: ${skipped.join(", ")}`,
    });
  }
  return verdicts;
}

/** Parse the collected rows a run wrote. */
export function loadRows(path: string): RowLike[] {
  if (!existsSync(path)) return [];
  return readFileSync(path, "utf8")
    .split("\n")
    .filter((line) => line.trim().length > 0)
    .flatMap((line) => {
      try {
        return [JSON.parse(line) as RowLike];
      } catch {
        return [];
      }
    });
}

/**
 * The archived report has to be reproducible from the archived run.
 *
 * `artifacts/acceptance/report.md` is the one artefact the whole retro argues
 * about, and it is a **recomputation** (`02ce73d`), not a re-measurement. That is
 * legitimate only while the recomputation is stable: if the evaluator drifts, the
 * published table starts describing a program that no longer exists, and nothing
 * notices because the file is checked in and never regenerated.
 *
 * Runs the compiled sibling entry point (`scripts/run.mjs` put us next to it, so
 * no second transpile is needed) and diffs the output byte for byte. `na` when
 * there is nothing to compare against, never `pass`.
 */
export async function judgeReportReproducible(
  root: string,
  entry: string | null,
): Promise<GateVerdict> {
  const name = "the archived report is reproducible";
  const artifact = join(root, "artifacts", "acceptance", "report.md");
  const runName = newestLiveRun(root);
  if (!existsSync(artifact) || runName === null) {
    return { name, ok: true, na: true, detail: "na: no archived report, or no collected run to recompute it from" };
  }
  if (entry === null || !existsSync(entry)) {
    return {
      name,
      ok: true,
      na: true,
      detail: `na: the evaluator entry point is not on disk beside this one (${entry ?? "unknown"}); ` +
        `run this through \`npm run gate:degeneration\` so the compiled sibling exists`,
    };
  }
  const outDir = join(root, ".tmp", "report-repro");
  rmSync(outDir, { recursive: true, force: true });
  const result = await capture(
    process.execPath,
    [
      entry,
      "--runs",
      join(root, "runs", "live", runName),
      "--rows-source",
      "live",
      "--out",
      outDir,
    ],
    { cwd: root, timeoutMs: 300_000 },
  );
  if (result.exitCode !== 0) {
    return {
      name,
      ok: false,
      detail: `the evaluator exited ${result.exitCode} on ${runName}: ${result.stderr.replace(/\s+/g, " ").trim().slice(0, 300)}`,
    };
  }
  const produced = join(outDir, "report.md");
  if (!existsSync(produced)) {
    return { name, ok: false, detail: `the evaluator wrote no report.md into ${outDir}` };
  }
  // Compared on content, not on line endings: `.gitattributes` rewrites the
  // working copy to CRLF on Windows, and a fresh checkout would otherwise turn
  // this into a false red that has nothing to do with the evaluator.
  const normalize = (text: string): string => text.replace(/\r\n/g, "\n");
  const expected = normalize(readFileSync(artifact, "utf8"));
  const actual = normalize(readFileSync(produced, "utf8"));
  if (expected === actual) {
    return { name, ok: true, detail: `${runName} recomputes to the same bytes as artifacts/acceptance/report.md` };
  }
  const expectedLines = expected.split("\n");
  const actualLines = actual.split("\n");
  const firstDiff = expectedLines.findIndex((line, index) => line !== actualLines[index]);
  return {
    name,
    ok: false,
    detail:
      `recomputing ${runName} no longer matches artifacts/acceptance/report.md ` +
      `(first difference at line ${firstDiff + 1}):\n` +
      `  published: ${(expectedLines[firstDiff] ?? "").slice(0, 200)}\n` +
      `  recomputed: ${(actualLines[firstDiff] ?? "").slice(0, 200)}\n` +
      `  Either the evaluator drifted - and every quoted number with it - or the report ` +
      `needs regenerating on purpose and committing with that decision`,
  };
}

/** Every sample file in a dataset directory, with its defect spans. */
export function loadSampleDefects(datasetDir: string): SampleDefect[] {
  const manifestPath = join(datasetDir, "manifest.json");
  if (!existsSync(manifestPath)) return [];
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
    samples?: Array<{ id?: unknown; sample_id?: unknown }>;
  };
  const ids = (manifest.samples ?? [])
    .map((sample) => (typeof sample.id === "string" ? sample.id : sample.sample_id))
    .filter((id): id is string => typeof id === "string");
  const samples: SampleDefect[] = [];
  for (const id of ids) {
    const path = join(datasetDir, "samples", `${id}.json`);
    if (!existsSync(path)) continue;
    const raw = JSON.parse(readFileSync(path, "utf8")) as { defects?: Array<Record<string, unknown>> };
    samples.push({ id, defects: raw.defects ?? [] });
  }
  return samples;
}

/** Newest `runs/live/*` directory that actually collected rows. */
function newestLiveRun(root: string): string | null {
  const base = join(root, "runs", "live");
  if (!existsSync(base)) return null;
  const candidates = readdirSync(base, { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort()
    .reverse();
  return candidates.find((name) => existsSync(join(base, name, "rows.jsonl"))) ?? null;
}

export function liveVerdicts(root = process.cwd()): GateVerdict[] {
  const scripts = (JSON.parse(readFileSync(join(root, "package.json"), "utf8")) as {
    scripts?: Record<string, string>;
  }).scripts ?? {};
  const verdicts: GateVerdict[] = [...judgeGateEntrypoints(scripts)];
  verdicts.push(judgeDefectSpans(loadSampleDefects(join(root, "datasets", "self-built"))));

  const reportPath = join(root, "artifacts", "acceptance", "report.md");
  const reportText = existsSync(reportPath) ? readFileSync(reportPath, "utf8") : null;
  const runName = newestLiveRun(root);
  if (runName === null) {
    verdicts.push({
      name: "line 3 groups one run of one sample",
      ok: true,
      na: true,
      detail: "na: no collected run under runs/live/ to group",
    });
    verdicts.push({
      name: "line 4 knows where its rows came from",
      ok: true,
      na: true,
      detail: "na: no collected run under runs/live/",
    });
    return verdicts;
  }

  const runDir = join(root, "runs", "live", runName);
  const rows = loadRows(join(runDir, "rows.jsonl"));
  const counts = new Map<string, number>();
  for (const row of rows) {
    const key = String(row.baseline ?? "");
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const grouping = judgePairGrouping(rows);
  verdicts.push({
    ...grouping,
    detail: `${grouping.detail} [${runName}: ${[...counts].map(([b, n]) => `${b} ${n}`).join(", ")}]`,
  });

  const manifestPath = join(runDir, "run.json");
  const manifest = existsSync(manifestPath)
    ? (JSON.parse(readFileSync(manifestPath, "utf8")) as { truncated?: unknown })
    : {};
  verdicts.push(
    judgeTruncatedRun({
      truncated: manifest.truncated === true,
      gateScorePublished: existsSync(join(root, "artifacts", "acceptance", "verdict.md")),
    }),
  );
  verdicts.push(
    judgeRowsSource({
      rowsSource: reportText === null ? "unknown" : (/source=(\w+)/.exec(reportText)?.[1] ?? "unknown"),
      runJsonPresent: existsSync(manifestPath),
      renderedText: reportText,
    }),
  );
  return verdicts;
}

export function formatVerdicts(verdicts: readonly GateVerdict[]): string {
  return verdicts
    .map(
      (verdict) =>
        `${verdict.ok ? (verdict.na === true ? "NA  " : "PASS") : "FAIL"} ${verdict.name} :: ${verdict.detail}`,
    )
    .join("\n");
}

async function main(): Promise<void> {
  const root = process.cwd();
  const verdicts = liveVerdicts(root);
  // The compiled sibling exists only when this ran through `scripts/run.mjs`; the
  // judge reports `na` rather than pretending it compared something.
  const entry = process.argv[1] === undefined ? null : join(dirname(process.argv[1]), "acceptance.js");
  verdicts.push(await judgeReportReproducible(root, entry));
  const failed = verdicts.filter((verdict) => !verdict.ok && verdict.na !== true).length;
  const na = verdicts.filter((verdict) => verdict.na === true).length;
  process.stdout.write(
    `SILENT-DEGENERATION GATE - the failures that print a number instead of throwing\n\n` +
      `${formatVerdicts(verdicts)}\n\n` +
      `${verdicts.length - failed - na} pass, ${na} na, ${failed} fail\n`,
  );
  if (failed > 0) process.exitCode = 1;
}

if (
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/silent-degeneration.ts") ||
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/silent-degeneration.js")
) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
