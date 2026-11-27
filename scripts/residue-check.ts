/**
 * Residue patrol: is something still running that a probe started and nobody
 * killed?
 *
 * Retro 2026-11-27, friction ②.
 *
 * A `pysemgrep --version` sat on one core from 15:38 and burned **five hours of
 * CPU**. Nothing looked for it. It was found by hand, days later, while chasing
 * a latency mystery - and killing it moved p50 by only ~10%, so it also cost
 * several hours of investigation aimed at the wrong cause. Two failures, one
 * cause: "is there a leftover process" was not a question any check asked.
 *
 * The rule is deliberately narrow, because a patrol that fires on a legitimately
 * running scan gets reclassified as noise and skipped:
 *
 *   residue = old **and** expensive.
 *
 * A short-lived child fails the age test; a long-lived idle agent fails the CPU
 * test. The 15:38 process failed neither: hours old, hours of CPU.
 *
 * "Could not look" is reported as a failure, not as a clean machine. That is the
 * same distinction `observeOrphanWriter` makes for a jsonl that stops growing,
 * and the same one the run manifest makes between `0` and `na`.
 */
import { captureSync } from "./capture.js";
import type { GateVerdict } from "./shared.js";
import { arg } from "./shared.js";

export interface ProcessEntry {
  name: string;
  pid: number;
  /** CPU consumed, milliseconds. */
  cpuMs: number;
  /** Age, milliseconds. `null` when the platform would not say (access denied on start time). */
  ageMs: number | null;
}

export interface ResidueLimits {
  /** Older than this is "old". */
  maxAgeMs: number;
  /** More CPU than this is "expensive". */
  maxCpuMs: number;
}

export const DEFAULT_LIMITS: ResidueLimits = { maxAgeMs: 10 * 60_000, maxCpuMs: 60_000 };

/**
 * Instrument processes plus the interpreter that runs the Python-based one.
 * `python` is here because `pysemgrep` *is* a python script: on Windows the
 * leftover process is `python.exe`, so a name list without it would have missed
 * the incident entirely.
 */
const WATCHED = /^(pysemgrep|semgrep|semgrep-core|code-review-graph|codereviewgraph|opencodereview|ocr|python3?|pythonw)(\.exe)?$/i;

export function classifyResidue(
  entries: readonly ProcessEntry[],
  limits: ResidueLimits = DEFAULT_LIMITS,
): GateVerdict[] {
  const watched = entries.filter((entry) => WATCHED.test(entry.name));
  const residue = watched.filter(
    (entry) => entry.ageMs !== null && entry.ageMs > limits.maxAgeMs && entry.cpuMs > limits.maxCpuMs,
  );
  const undated = watched.filter((entry) => entry.ageMs === null);

  const verdicts: GateVerdict[] = [];
  verdicts.push({
    name: "no leftover instrument process",
    ok: residue.length === 0,
    detail:
      residue.length === 0
        ? `${watched.length} watched process(es) present, none both older than ` +
          `${Math.round(limits.maxAgeMs / 60_000)} min and past ${Math.round(limits.maxCpuMs / 1000)} s CPU`
        : residue
            .map(
              (entry) =>
                `${entry.name} pid ${entry.pid}: ${Math.round((entry.ageMs ?? 0) / 60_000)} min old, ` +
                `${Math.round(entry.cpuMs / 1000)} s CPU`,
            )
            .join("; ") +
          ` - a probe that never exited is still holding a core. It skews every latency measured ` +
          `next to it, and the last time this happened it was found days later and blamed for a ` +
          `4x slowdown it caused ~10% of. Kill the tree, then re-run the patrol`,
  });
  if (undated.length > 0) {
    // A watched process whose start time could not be read is not evidence of
    // anything; saying so is the point.
    verdicts.push({
      name: "residue patrol could date every match",
      ok: false,
      na: true,
      detail:
        `na: ${undated.length} watched process(es) would not report a start time ` +
        `(${undated.map((entry) => `${entry.name} ${entry.pid}`).join(", ")}): ` +
        `age is unmeasurable, so "old and expensive" cannot be decided`,
    });
  }
  return verdicts;
}

/**
 * Enumerate the process table.
 *
 * `Get-CimInstance Win32_Process` would give the command line, which is what you
 * actually want for telling `python -m semgrep` apart from an unrelated python.
 * It is access-denied in this environment, so the check uses `Get-Process` and
 * says what it could not see. Falling back to a name list is a real limitation;
 * pretending the command line was inspected would be a worse one.
 */
export async function enumerateProcesses(): Promise<ProcessEntry[] | null> {
  try {
    if (process.platform === "win32") return await enumerateWindows();
    return await enumeratePosix();
  } catch {
    return null;
  }
}

async function enumerateWindows(): Promise<ProcessEntry[]> {
  // Unfiltered on purpose: the watched set is applied in TypeScript, so an empty
  // result means the enumeration failed rather than that the machine is clean.
  const script = [
    "Get-Process -ErrorAction SilentlyContinue |",
    "ForEach-Object {",
    "  $started = $null;",
    "  try { $started = $_.StartTime.ToUniversalTime().ToString('o') } catch { }",
    "  [pscustomobject]@{ name = $_.ProcessName; pid = $_.Id;",
    "    cpuMs = [int][math]::Round(($_.CPU * 1000)); startedAt = $started }",
    "} | ConvertTo-Json -Compress",
  ].join(" ");
  // Windows PowerShell rather than `pwsh`: this is the one that exists on a
  // stock image, and the check has to run before anyone has installed anything.
  // Captured through files: a piped child is `spawn EPERM` in the default
  // sandbox, which would make the patrol unable to look exactly where looking
  // matters most.
  const result = captureSync(
    "powershell.exe",
    ["-NoProfile", "-NonInteractive", "-Command", script],
    { timeoutMs: 60_000 },
  );
  if (result.exitCode !== 0) {
    throw new Error(`powershell exited ${result.exitCode}: ${result.stderr.trim().slice(0, 200)}`);
  }
  const text = `${result.stdout ?? ""}`.trim();
  if (text.length === 0) return [];
  const parsed = JSON.parse(text) as unknown;
  const list = Array.isArray(parsed) ? parsed : [parsed];
  const now = Date.now();
  return list.map((raw) => {
    const record = raw as { name?: unknown; pid?: unknown; cpuMs?: unknown; startedAt?: unknown };
    const startedAt = typeof record.startedAt === "string" ? Date.parse(record.startedAt) : NaN;
    return {
      name: String(record.name ?? ""),
      pid: Number(record.pid ?? 0),
      cpuMs: Number(record.cpuMs ?? 0),
      ageMs: Number.isFinite(startedAt) ? now - startedAt : null,
    };
  });
}

async function enumeratePosix(): Promise<ProcessEntry[]> {
  // `etimes` is seconds since start, `time` is cumulative CPU as [[dd-]hh:]mm:ss.
  const result = captureSync("ps", ["-eo", "pid=,etimes=,time=,comm="], { timeoutMs: 60_000 });
  if (result.exitCode !== 0) throw new Error(`ps exited ${result.exitCode}`);
  const entries: ProcessEntry[] = [];
  for (const line of `${result.stdout ?? ""}`.split("\n")) {
    const match = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.+)$/.exec(line);
    if (match === null) continue;
    entries.push({
      name: (match[4] ?? "").split("/").pop() ?? "",
      pid: Number(match[1]),
      cpuMs: parseCpuTime(match[3] ?? ""),
      ageMs: Number(match[2]) * 1000,
    });
  }
  return entries;
}

/** `[[dd-]hh:]mm:ss` -> milliseconds. */
export function parseCpuTime(text: string): number {
  const [days = "0", rest] = text.includes("-") ? (text.split("-") as [string, string]) : ["0", text];
  const parts = rest.split(":").map((part) => Number(part));
  if (parts.some((part) => !Number.isFinite(part))) return 0;
  const seconds =
    parts.length === 3
      ? (parts[0] ?? 0) * 3600 + (parts[1] ?? 0) * 60 + (parts[2] ?? 0)
      : parts.length === 2
        ? (parts[0] ?? 0) * 60 + (parts[1] ?? 0)
        : (parts[0] ?? 0);
  return (Number(days) * 86_400 + seconds) * 1000;
}

/**
 * Did the patrol actually look?
 *
 * Split out from `classifyResidue` because "nothing was found" and "nothing was
 * checked" must not render the same way - the whole incident is that nobody was
 * looking. The process table is enumerated unfiltered and the watched names are
 * matched here, so an empty table really does mean the enumeration failed.
 */
export function judgePatrolCoverage(entries: readonly ProcessEntry[] | null): GateVerdict {
  return {
    name: "residue patrol looked",
    ok: entries !== null && entries.length > 0,
    detail:
      entries === null
        ? `the process table could not be enumerated. That is not a clean machine, it is an ` +
          `unexamined one, and the check that would have caught the 15:38 process cannot tell ` +
          `the two apart unless it says so`
        : entries.length === 0
          ? `the enumeration returned no processes at all, which no running machine does: the view ` +
            `was truncated, and a truncated view reports a clean machine`
          : `${entries.length} process(es) enumerated, ${entries.filter((entry) => WATCHED.test(entry.name)).length} watched`,
  };
}

async function main(): Promise<void> {
  const phase = arg("--phase", "before");
  const entries = await enumerateProcesses();
  const coverage = judgePatrolCoverage(entries);
  const verdicts: GateVerdict[] =
    entries === null ? [coverage] : [coverage, ...classifyResidue(entries)];
  const failed = verdicts.filter((verdict) => !verdict.ok && verdict.na !== true).length;
  process.stdout.write(
    `RESIDUE PATROL (${phase})\n` +
      `${verdicts
        .map(
          (verdict) =>
            `${verdict.ok ? (verdict.na === true ? "NA  " : "PASS") : "FAIL"} ${verdict.name} :: ${verdict.detail}`,
        )
        .join("\n")}\n`,
  );
  if (failed > 0) process.exitCode = 1;
}

if (
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/residue-check.ts") ||
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/residue-check.js")
) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
