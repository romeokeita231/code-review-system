/**
 * The instrument gate: is this machine, running this build, the thing the
 * frozen numbers describe?
 *
 * Retro 2026-11-27, frictions ① and ④.
 *
 * ① Environment drift, invisible to every gate.
 *   `frozen.budgets.crg_query_ms` is `ceil(1.5 x p99)` of one `impact` call, and
 *   preflight compared the *config* against that frozen number. The machine was
 *   in no gate at all. On 2026-11-19 and again on 2026-11-20 the same commits,
 *   the same `code-review-graph` 2.3.9 and an unchanged `configs/` measured
 *   pooled p99 2042 / 2672 ms against the archived 662 ms. The floor those days
 *   was `ceil(1.5 x 2672) = 4008 ms`, and `4008 + 5000 > 8000`: no config could
 *   have run, and a config still sitting at the frozen 993 ms passed preflight
 *   and silently killed every `impact` call - the source disappears, the row
 *   says tier 0, and nothing reports a failure.
 *   ADR-0009 states the rule the gate was built on: *the machine holds no p99,
 *   only the inequality and the arithmetic are verified*. That is exactly why
 *   nothing noticed. This file is the missing half: take the p99 on *this*
 *   machine, and refuse when the floor stops describing it.
 *
 * ④ A mechanical source degrades silently.
 *   `semgrep` stopped answering here (single-file scan > 180 s, `--version` the
 *   same). #49 turned the hang into a timeout, so every scan is now killed at
 *   `semgrepKillMs` and the row reads like "semgrep found nothing here". And
 *   `semgrep_kill_ms = 975` rests on one 2026-11-13 observation - the
 *   preregistration says so itself: "single observation, not a distribution".
 *   A floor derived from one sample cannot tell "warm 650 ms" from "hangs
 *   forever", so the gate refuses a floor whose own derivation says that, and
 *   probes the binary inside the budget the scan path gives it.
 *
 * The judging functions are pure so `scripts/gate-replay.ts` can replay the two
 * incidents through them and assert they go red.
 */
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";
import { capture } from "./capture.js";
import { loadFrozenBudgets, type FrozenBudgets } from "./frozen.js";
import { arg, type GateVerdict } from "./shared.js";

export type { GateVerdict };

/**
 * The archived table used n = 44 (10 / 14 / 20 over three pinned checkouts).
 * Twelve is the floor at which "p99" at least reaches beyond the median: with
 * nearest-rank over 12 samples the p99 *is* the maximum, which is an upper
 * bound. For a **floor** that bias is fail-safe - it can only over-refuse, never
 * silently pass - so a small n is acceptable if it is stated.
 */
export const MIN_SAMPLES = 12;

export interface Budgets {
  crgQueryMs: number;
  semgrepKillMs: number;
  callMs: number;
}

export interface ImpactMeasurement {
  /** What was timed. "the three pinned checkouts" is not reproducible on demand. */
  workload: string;
  files: number;
  /** The tell the 11-20 investigation used: it moves with the machine, not the query. */
  buildMs: number | null;
  /** Why the workload had to step down, or null when it built at full size. */
  buildNote?: string | null;
  version: string;
  /**
   * How the child's output was captured. `file` is a lower bound on a `pipe`
   * number, because a file handle skips the pipe's copying; recorded so the
   * comparison against a piped baseline is not silently assumed to be exact.
   */
  stdio: "file";
  /** Calls attempted. */
  n: number;
  /** Calls that answered. A p99 over a biased subset is not a p99. */
  answered: number;
  p50: number | null;
  p99: number | null;
  samples: number[];
}

/** Nearest rank, the estimator the archived table used. */
export function nearestRankP(values: readonly number[], percentile: number): number | null {
  if (values.length === 0) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil(percentile * sorted.length);
  const index = Math.min(sorted.length, Math.max(1, rank)) - 1;
  return sorted[index] ?? null;
}

/** ADR-0009: the floor is `ceil(1.5 x p99)`, an inequality, not a target. */
export function impactFloor(p99: number): number {
  return Math.ceil(p99 * 1.5);
}

export function judgeMachine(
  measured: ImpactMeasurement,
  frozen: Pick<FrozenBudgets, "crg_query_ms">,
  budgets: Budgets,
): GateVerdict[] {
  const verdicts: GateVerdict[] = [];
  const measuredOk =
    measured.n >= MIN_SAMPLES && measured.answered === measured.n && measured.p99 !== null;
  verdicts.push({
    name: "impact p99 measured",
    ok: measuredOk,
    detail:
      measured.p99 === null
        ? `${measured.n} calls attempted, none answered: there is no latency here, only a binary ` +
          `that does not run` +
          (measured.buildNote === null || measured.buildNote === undefined
            ? ""
            : `. The workload would not index either: ${measured.buildNote}`)
        : measured.n < MIN_SAMPLES
          ? `n=${measured.n} < ${MIN_SAMPLES}: with fewer samples the nearest-rank p99 is not a p99, ` +
            `it is one observation wearing the name (that is friction ④ arriving by another door)`
          : measured.answered !== measured.n
            ? `${measured.answered}/${measured.n} calls answered; the p99 is over the survivors, ` +
              `so it is biased low and the floor built on it would be too`
            : `${measured.n} calls, all answered; p50 ${measured.p50 ?? "?"} ms, p99 ${measured.p99} ms`,
  });

  const p99 = measured.p99;
  if (p99 === null) return verdicts;
  const floor = impactFloor(p99);

  // (a) The pinned derivation: does the frozen value still describe this machine?
  verdicts.push({
    name: "frozen floor describes this machine",
    ok: floor <= frozen.crg_query_ms,
    detail:
      floor <= frozen.crg_query_ms
        ? `ceil(1.5 x ${p99}) = ${floor} ms <= frozen ${frozen.crg_query_ms} ms`
        : `ceil(1.5 x ${p99}) = ${floor} ms > frozen ${frozen.crg_query_ms} ms: the pinned floor ` +
          `was derived on a machine whose p99 was ${Math.floor(frozen.crg_query_ms / 1.5)} ms; ` +
          `this one needs ${floor} ms, so every number quoted against the pin is a number about ` +
          `another machine (ADR-0009 asks for the inequality; the pin cannot supply it here)`,
  });

  // (b) The configured budget: does the config about to run cover this machine?
  verdicts.push({
    name: "configured budget covers this machine",
    ok: budgets.crgQueryMs >= floor,
    detail:
      budgets.crgQueryMs >= floor
        ? `config crgQueryMs ${budgets.crgQueryMs} ms >= floor ${floor} ms`
        : `config crgQueryMs ${budgets.crgQueryMs} ms < floor ${floor} ms: every impact call is ` +
          `killed at the config budget, the tier falls back to the static ladder, and the row ` +
          `claims the file has no importers - a false statement about the repository, produced ` +
          `by a number, with no error printed`,
  });

  const prePath = budgets.semgrepKillMs + Math.max(budgets.crgQueryMs, floor);
  verdicts.push({
    name: "pre path fits the call budget",
    ok: prePath <= budgets.callMs,
    detail:
      prePath <= budgets.callMs
        ? `${budgets.semgrepKillMs} + max(${budgets.crgQueryMs}, ${floor}) = ${prePath} ms ` +
          `<= callMs ${budgets.callMs} ms`
        : `${budgets.semgrepKillMs} + max(${budgets.crgQueryMs}, ${floor}) = ${prePath} ms ` +
          `> callMs ${budgets.callMs} ms: the two pre-path floors do not fit in one call, so the ` +
          `run cannot be made to work by picking a budget - the machine is outside the supported ` +
          `environment and the comparable number has to be taken elsewhere`,
  });
  return verdicts;
}

/**
 * ④(b): a floor whose own derivation says "single observation" is not a floor.
 *
 * The preregistration is quoted rather than second-guessed: it already carries
 * the evidence level, and the gate only refuses to build a one-shot measurement
 * on top of a value that declares it has no distribution behind it.
 */
export function judgeSemgrepFloor(frozen: FrozenBudgets): GateVerdict {
  const latency = frozen.semgrep_latency;
  if (latency !== null && latency.n >= MIN_SAMPLES) {
    return {
      name: "semgrep floor has a distribution",
      ok: true,
      detail: `n=${latency.n}, p99 ${latency.p99} ms`,
    };
  }
  const declared =
    frozen.semgrep_derivation?.match(/single observation[^.]*/i)?.[0] ?? null;
  return {
    name: "semgrep floor has a distribution",
    ok: false,
    detail:
      (latency === null
        ? `frozen.budgets has no semgrep_latency samples`
        : `frozen.budgets.semgrep_latency has n=${latency.n} < ${MIN_SAMPLES}`) +
      `, so \`semgrep_kill_ms = ${frozen.semgrep_kill_ms}\` is derived from a sample of one` +
      (declared === null ? "" : ` (the preregistration says so: "${declared}")`) +
      `. One sample cannot separate "warm 650 ms" from "hangs forever", which is the state this ` +
      `machine was in: take ${MIN_SAMPLES} warm samples, or the scan's kill budget is a guess ` +
      `that turns every unanswered scan into "found nothing here"`,
  };
}

export interface SemgrepProbe {
  /** `ok` answered; `timeout` never returned; `error` returned a failure. */
  kind: "ok" | "timeout" | "error";
  elapsedMs: number;
  timeoutMs: number;
  detail: string;
}

export function judgeSemgrepAnswer(probe: SemgrepProbe): GateVerdict {
  if (probe.kind === "ok") {
    return {
      name: "semgrep answers inside its budget",
      ok: true,
      detail: `${probe.detail} in ${probe.elapsedMs} ms (budget ${probe.timeoutMs} ms)`,
    };
  }
  // A hang and a fast failure are different diagnoses and get different
  // sentences. The second is the one this machine actually produces:
  // `CertOpenSystemStore returned NULL` from semgrep's OCaml CA bootstrap.
  return {
    name: "semgrep answers inside its budget",
    ok: false,
    detail:
      probe.kind === "timeout"
        ? `no answer within ${probe.timeoutMs} ms (${probe.detail}): #49 kills the tree on timeout, ` +
          `so the run degrades instead of hanging - every scan becomes a silent "found nothing here"`
        : `answered with a failure in ${probe.elapsedMs} ms (${probe.detail}): semgrep cannot get ` +
          `past its own startup here, so it never matches a rule. It exits non-zero, which the ` +
          `source reports as "no findings", and the blocking path is then absent rather than ` +
          `measured - the same row either way`,
  };
}

export async function probeSemgrep(timeoutMs: number): Promise<SemgrepProbe> {
  const started = Date.now();
  const result = await capture("semgrep", ["--version"], { timeoutMs });
  const elapsedMs = Date.now() - started;
  // `\r` first: a Windows CRLF left on the first line would break the one-line
  // verdict the whole table is built on.
  const text = `${result.stdout}${result.stderr}`.replace(/\r/g, "").trim();
  const firstLine = text.split("\n")[0] ?? "";
  const kind: SemgrepProbe["kind"] =
    result.exitCode === 0 && text.length > 0 ? "ok" : result.timedOut ? "timeout" : "error";
  return {
    kind,
    elapsedMs,
    timeoutMs,
    detail:
      kind === "timeout"
        ? "timed out"
        : firstLine.slice(0, 160) || text.split("\n").filter((line) => line.trim().length > 0).pop()?.slice(0, 160) || `exit ${result.exitCode}`,
  };
}

/**
 * Time the `impact` call `CrgTriage.analyze` makes, on a workload this repo can
 * always produce.
 *
 * The archived table used the three pinned checkouts. They are not on this
 * machine and pinning a network clone inside a gate trades a measurement for a
 * download. The property the decision rests on is recorded in the same table:
 * *latency is process start, not graph size - 674 files and 10 differ by 8%*.
 * So the workload is a 10-file tree copied out of `src/`, and the verdict says
 * so in `workload`. What is lost is the right to call the number "the archived
 * p99"; what is kept is the only thing the gate needs, which is a comparable
 * number on this machine today.
 */
export async function measureImpact(options: {
  repo: string;
  samples?: number;
  command?: string;
}): Promise<ImpactMeasurement> {
  const command = options.command ?? "code-review-graph";
  const samples = Math.max(1, options.samples ?? MIN_SAMPLES);
  const repo = resolve(options.repo);

  const versionProbe = await capture(command, ["--version"], { timeoutMs: 60_000 });
  const versionLine = `${versionProbe.stdout}${versionProbe.stderr}`.trim().split("\n")[0] ?? "";
  const version = /\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/.exec(versionLine)?.[0] ?? "unknown";

  const candidates = await trackedTs(repo);
  const workloadRoot = await mkdtemp(join(tmpdir(), "crs-instrument-"));
  try {
    // `code-review-graph build` fans out through Python's `ProcessPoolExecutor`,
    // and on Windows that creates a named pipe - refused here with
    // `PermissionError [WinError 5]`. The pool only engages above a size
    // threshold, so the workload steps down until a tree builds. The size is
    // recorded, and the property the decision rests on survives the step-down:
    // latency is process start, not graph size (674 files and 10 differ by 8%).
    const sizes = [...new Set([10, 4, 1, 0].filter((size) => size <= Math.max(1, candidates.length)))].sort(
      (a, b) => b - a,
    );
    const attempts: string[] = [];
    let chosen: { dir: string; files: string[]; buildMs: number } | null = null;
    for (const size of sizes) {
      const files = candidates.slice(0, Math.max(1, size));
      const dir = join(workloadRoot, `w${size}`);
      for (const file of files) {
        const target = join(dir, file);
        await mkdir(resolve(target, ".."), { recursive: true });
        await writeFile(target, await readFile(join(repo, file), "utf8"), "utf8");
      }
      const started = Date.now();
      const build = await capture(
        command,
        ["build", "--repo", dir, "--skip-flows", "--skip-postprocess"],
        { cwd: dir, timeoutMs: 180_000 },
      );
      if (build.exitCode === 0 && !build.timedOut) {
        chosen = { dir, files, buildMs: Date.now() - started };
        break;
      }
      attempts.push(`${files.length} file(s): ${lastMeaningfulLine(build.stderr) || `exit ${build.exitCode}`}`);
    }

    if (chosen === null) {
      return {
        workload: `${repo} (no workload tree would build)`,
        files: 0,
        buildMs: null,
        buildNote: attempts.join("; "),
        version,
        stdio: "file",
        n: samples,
        answered: 0,
        p50: null,
        p99: null,
        samples: [],
      };
    }

    const samplesMs: number[] = [];
    let answered = 0;
    for (let index = 0; index < samples; index += 1) {
      const file = chosen.files[index % chosen.files.length] ?? "";
      const started = Date.now();
      const result = await capture(
        command,
        ["impact", "--repo", chosen.dir, "--files", file],
        { cwd: chosen.dir, timeoutMs: 60_000 },
      );
      if (result.exitCode === 0 && !result.timedOut) {
        answered += 1;
        samplesMs.push(Date.now() - started);
      }
    }

    return {
      workload:
        `${chosen.files.length}-file tree copied from ${repo}` +
        `${chosen.files.length === Math.min(10, candidates.length) ? "" : ` (stepped down from ${Math.min(10, candidates.length)}: ${attempts.join("; ")})`}` +
        ` (archived table: three pinned checkouts)`,
      files: chosen.files.length,
      buildMs: chosen.buildMs,
      buildNote: attempts.length === 0 ? null : attempts.join("; "),
      version,
      stdio: "file",
      n: samples,
      answered,
      p50: nearestRankP(samplesMs, 0.5),
      p99: nearestRankP(samplesMs, 0.99),
      samples: samplesMs,
    };
  } finally {
    await rm(workloadRoot, { recursive: true, force: true, maxRetries: 3 });
  }
}

/** The line a failure is actually reported on, not the traceback header. */
function lastMeaningfulLine(text: string): string {
  const lines = text
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  // Case-insensitive on purpose: semgrep writes "Fatal error: exception ..." in
  // lower case, and a capitalised-only match reported the traceback instead.
  const errorLine = lines.find(
    (line) => /error|exception|failure/i.test(line) && !/^traceback/i.test(line),
  );
  return (errorLine ?? lines[0] ?? "").slice(0, 200);
}

/** Tracked TypeScript files, sorted, so the workload is the same every run. */
async function trackedTs(repo: string): Promise<string[]> {
  const listed = await capture("git", ["ls-files", "src"], { cwd: repo, timeoutMs: 60_000 });
  const fromGit = `${listed.stdout ?? ""}`
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => /\.tsx?$/.test(line));
  if (fromGit.length > 0) return [...new Set(fromGit)].sort();
  const walked: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (/\.tsx?$/.test(entry.name)) walked.push(relative(repo, path).replace(/\\/g, "/"));
    }
  };
  await walk(join(repo, "src"));
  return walked.sort();
}

export function readBudgets(configPath: string): Budgets {
  const raw = JSON.parse(readFileSync(configPath, "utf8")) as {
    budgets?: { crgQueryMs?: unknown; semgrepKillMs?: unknown; callMs?: unknown };
  };
  return {
    crgQueryMs: Number(raw.budgets?.crgQueryMs ?? 0),
    semgrepKillMs: Number(raw.budgets?.semgrepKillMs ?? 0),
    callMs: Number(raw.budgets?.callMs ?? 0),
  };
}

async function main(): Promise<void> {
  const configPath = resolve(arg("--config", "configs/b4.json"));
  const samples = Number(arg("--samples", String(MIN_SAMPLES)));
  const budgets = readBudgets(configPath);
  const frozen = loadFrozenBudgets();
  if (frozen === null) {
    throw new Error("artifacts/preregistration.json has no frozen.budgets: there is no floor to check against");
  }

  const measured = await measureImpact({ repo: process.cwd(), samples });
  const verdicts: GateVerdict[] = [
    ...judgeMachine(measured, frozen, budgets),
    judgeSemgrepAnswer(await probeSemgrep(budgets.semgrepKillMs || 5_000)),
    judgeSemgrepFloor(frozen),
  ];

  const rows = verdicts.map(
    (verdict) => `${verdict.ok ? "PASS" : "FAIL"} ${verdict.name} :: ${verdict.detail}`,
  );
  const failed = verdicts.filter((verdict) => !verdict.ok).length;
  process.stdout.write(
    `INSTRUMENT GATE - ${measured.version} on this machine\n` +
      `workload: ${measured.workload}\n` +
      `build_ms: ${measured.buildMs ?? "na"} (the tell: it moves with the machine, not the query)\n` +
      `config: ${relative(process.cwd(), configPath).replace(/\\/g, "/")}  ` +
      `crgQueryMs ${budgets.crgQueryMs}  semgrepKillMs ${budgets.semgrepKillMs}  callMs ${budgets.callMs}\n\n` +
      `${rows.join("\n")}\n\n` +
      `${failed === 0 ? "all clean: this machine is the one the frozen numbers describe" : `REFUSING: ${failed} instrument check(s) red`}\n`,
  );
  if (failed > 0) process.exitCode = 1;
}

if (process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/instrument-gate.ts") ||
    process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/instrument-gate.js")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
