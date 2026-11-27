/**
 * What this machine can actually do, in one command.
 *
 * Not a gate: nothing here passes or fails. It is the lookup that replaces
 * re-deriving the sandbox's shape one `EPERM` at a time.
 *
 * Why it exists: on 2026-11-27 four separate throwaway scripts were written to
 * establish facts that are the same in every session on this host -
 *
 *   - a child spawned with **piped** stdio is `spawn EPERM`; a child whose
 *     stdout is a **real file handle** runs and its output is readable
 *     (`scripts/capture.ts` exists for exactly this)
 *   - `pwsh` is not on PATH; `powershell.exe` is
 *   - `code-review-graph impact` works, `build` can fail on its Python
 *     process pool (`mp.Pipe` is a named pipe, `PermissionError [WinError 5]`)
 *   - `semgrep` here fails fast (`CertOpenSystemStore returned NULL`) rather
 *     than hanging, and both read as "no findings" to the source
 *
 * `.tmp/` held 193 files of the same investigations. The fix is not a paragraph
 * telling the next agent to remember: it is one command whose output is the
 * answer, and one pointer to it that fires on the symptom.
 *
 *   npm run env:probe
 */
import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { capture, captureSync } from "./capture.js";

interface Row {
  probe: string;
  result: string;
  /** What it means for anything that shells out from here. */
  consequence: string;
}

async function main(): Promise<void> {
  const rows: Row[] = [];
  const command = process.platform === "win32" ? "powershell.exe" : "sh";

  rows.push({
    probe: "runtime",
    result: `node ${process.version} on ${process.platform}/${process.arch}`,
    consequence: "python and powershell are only reachable as child processes",
  });

  // 1. piped stdio -----------------------------------------------------------
  let piped = "";
  try {
    piped = execFileSync(process.execPath, ["-e", "process.stdout.write('ok')"], {
      encoding: "utf8",
      timeout: 20_000,
    });
    rows.push({ probe: "spawn + pipe", result: `ok (${piped})`, consequence: "execa and execFileSync work here" });
  } catch (error) {
    piped = "";
    rows.push({
      probe: "spawn + pipe",
      result: `fails: ${(error as NodeJS.ErrnoException).code ?? "error"}`,
      consequence:
        "execa, execFileSync and every esbuild consumer (tsx, vitest, vite) cannot start. " +
        "Use scripts/capture.ts, which redirects to a file handle instead",
    });
  }

  // 2. file-redirected stdio -------------------------------------------------
  const redirected = captureSync(process.execPath, ["-e", "process.stdout.write('ok')"], {
    timeoutMs: 20_000,
  });
  rows.push({
    probe: "spawn + file handle",
    result: `exit ${redirected.exitCode}, stdout ${JSON.stringify(redirected.stdout)}`,
    consequence:
      redirected.stdout === "ok"
        ? "capture.ts is the working path for anything a gate must read"
        : "capture.ts does not work either: gates that need a child's output cannot run here",
  });

  // 3. shells ----------------------------------------------------------------
  for (const shell of ["powershell.exe", "pwsh"]) {
    const which = captureSync(process.platform === "win32" ? "where.exe" : "which", [shell], {
      timeoutMs: 20_000,
    });
    rows.push({
      probe: shell,
      result: which.exitCode === 0 ? which.stdout.trim().split(/\r?\n/)[0] ?? "found" : "not on PATH",
      consequence:
        shell === "powershell.exe"
          ? "residue-check enumerates the process table through this one"
          : "not available here; do not script against it",
    });
  }
  void command;

  // 4. version control -------------------------------------------------------
  const head = captureSync("git", ["rev-parse", "--short", "HEAD"], { timeoutMs: 20_000 });
  rows.push({
    probe: "git",
    result: head.exitCode === 0 ? head.stdout.trim() : `exit ${head.exitCode}`,
    consequence: "'which commit' has an answer, so repo-identity can record it",
  });

  // 5. the graph CLI ---------------------------------------------------------
  const crgVersion = captureSync("code-review-graph", ["--version"], { timeoutMs: 60_000 });
  const crgText = crgVersion.stdout.trim() || crgVersion.stderr.trim().split(/\r?\n/)[0] || "no output";
  rows.push({
    probe: "code-review-graph --version",
    result: `exit ${crgVersion.exitCode}: ${crgText.slice(0, 80)}`,
    consequence: "tier assignment depends on this binary, so its identity is recorded per run",
  });

  // 6. build vs query, on a one-file tree ------------------------------------
  const dir = mkdtempSync(join(tmpdir(), "crs-env-probe-"));
  try {
    writeFileSync(join(dir, "probe.ts"), "export const probe = 1;\n", "utf8");
    const buildStarted = Date.now();
    const build = await capture(
      "code-review-graph",
      ["build", "--repo", dir, "--skip-flows", "--skip-postprocess"],
      { cwd: dir, timeoutMs: 120_000 },
    );
    rows.push({
      probe: "code-review-graph build (1 file)",
      result:
        build.exitCode === 0
          ? `exit 0 in ${Date.now() - buildStarted} ms`
          : `exit ${build.exitCode}: ${lastError(build.stderr)}`,
      consequence:
        build.exitCode === 0
          ? "an index can be built here"
          : "no index can be built here: impact can only run against one built elsewhere, " +
            "and gate:machine steps the workload down until a tree builds",
    });
    if (build.exitCode === 0) {
      const started = Date.now();
      const impact = await capture(
        "code-review-graph",
        ["impact", "--repo", dir, "--files", "probe.ts"],
        { cwd: dir, timeoutMs: 60_000 },
      );
      rows.push({
        probe: "code-review-graph impact (1 call)",
        result: impact.exitCode === 0 ? `${Date.now() - started} ms` : `exit ${impact.exitCode}: ${lastError(impact.stderr)}`,
        consequence: "this is the latency the frozen crg_query_ms floor is derived from",
      });
    }
  } finally {
    rmSync(dir, { recursive: true, force: true, maxRetries: 3 });
  }

  // 7. semgrep ---------------------------------------------------------------
  const semgrepStarted = Date.now();
  const semgrep = await capture("semgrep", ["--version"], { timeoutMs: 5_000 });
  const semgrepMs = Date.now() - semgrepStarted;
  rows.push({
    probe: "semgrep --version",
    result:
      semgrep.exitCode === 0
        ? `${semgrepMs} ms: ${semgrep.stdout.trim().split(/\r?\n/)[0] ?? ""}`
        : semgrep.timedOut
          ? `no answer in ${semgrepMs} ms (killed at the scan's own budget)`
          : `${semgrepMs} ms, exit ${semgrep.exitCode}: ${lastError(semgrep.stderr)}`,
    consequence:
      semgrep.exitCode === 0
        ? "the blocking path can be measured here"
        : "the blocking path is absent here: every scan reads as \"found nothing\", which is what " +
          "gate:machine refuses",
  });

  // 8. what the missing pipe costs ------------------------------------------
  rows.push({
    probe: "npm test (vitest)",
    result: piped.length > 0 ? "should start" : "cannot start: vitest loads its config through esbuild",
    consequence:
      piped.length > 0
        ? "run the suite locally"
        : "the test suite is a CI-only guardrail on this host; `npm run gate:all` is what runs here",
  });

  const width = Math.max(...rows.map((row) => row.probe.length));
  process.stdout.write(
    "ENV PROBE - what this machine can do. Nothing here passes or fails.\n" +
      (piped.length > 0
        ? ""
        : "\nThe one asymmetry to remember: piped stdio is refused, a file handle is not.\n") +
      "\n" +
      rows
        .map((row) => `${row.probe.padEnd(width)}  ${row.result}\n${" ".repeat(width)}  -> ${row.consequence}`)
        .join("\n") +
      "\n",
  );
}

/** The line a failure is actually reported on, not the traceback header. */
function lastError(text: string): string {
  const lines = text
    .replace(/\r/g, "")
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  // Case-insensitive: semgrep writes "Fatal error: exception ...", with both
  // words lowercase, and a capitalised-only match walked straight past it.
  const errorLine = lines.find(
    (line) => /error|exception|failure/i.test(line) && !/^traceback/i.test(line),
  );
  return (errorLine ?? lines[0] ?? "").slice(0, 140);
}

if (
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/env-probe.ts") ||
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/env-probe.js")
) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
