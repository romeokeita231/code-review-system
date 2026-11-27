/**
 * Capturing a child process's output in the default sandbox.
 *
 * Measured on this machine, 2026-11-27, in the default DSH sandbox:
 *
 *   execFileSync("git", ["rev-parse", ...])        -> spawn EPERM
 *   spawnSync("git", [...], { encoding: "utf8" })  -> spawn EPERM
 *   spawnSync("where.exe", [...], stdio: [file FDs]) -> status 0, output readable
 *
 * Piped stdio is a named pipe, and the sandbox refuses one. A real file handle
 * is not a pipe, so redirecting the child's stdout/stderr to files works. This
 * is the same boundary that makes `esbuild` (IPC pipe) and `vitest` (esbuild)
 * unable to start, seen from the other side.
 *
 * Why this matters more than it looks: `execaRunner` - the runner `CrgTriage`
 * and the semgrep source actually use - pipes. So in the default sandbox **no
 * measurement of any external tool can be taken at all**, which is why every
 * gate in this directory captures through files instead. The gates are the only
 * part of the pipeline that has to work here; the drill itself is a
 * non-sandbox activity and keeps using execa.
 *
 * The bias this introduces is recorded rather than hidden: a file handle skips
 * the pipe's copying, so a latency captured this way is a lower bound. The
 * dominant term is process start (the archived table: 674 files and 10 files
 * differ by 8%), so the difference is a few milliseconds against a floor with
 * 50% headroom - but it is a real direction, and it is the safe-*looking* one.
 */
import { spawn, spawnSync } from "node:child_process";
import { closeSync, mkdtempSync, openSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { TOOL_ENV, killProcessTree } from "../src/config/index.js";

export interface CaptureResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

export interface CaptureOptions {
  cwd?: string;
  /** Milliseconds; the whole tree is killed, not just the direct child (#49). */
  timeoutMs?: number;
  env?: NodeJS.ProcessEnv;
}

function scratch(name: string): { dir: string; out: string; err: string } {
  const dir = mkdtempSync(join(tmpdir(), `crs-capture-${name}-`));
  return { dir, out: join(dir, "stdout"), err: join(dir, "stderr") };
}

/** Synchronous variant, for short-lived commands (git, `where`). */
export function captureSync(file: string, args: string[], options: CaptureOptions = {}): CaptureResult {
  const { dir, out, err } = scratch("sync");
  const outFd = openSync(out, "w");
  const errFd = openSync(err, "w");
  try {
    const result = spawnSync(file, args, {
      cwd: options.cwd,
      env: options.env ?? { ...process.env, ...TOOL_ENV },
      stdio: ["ignore", outFd, errFd],
      windowsHide: true,
      timeout: options.timeoutMs ?? 60_000,
    });
    return {
      stdout: safeRead(out),
      stderr: safeRead(err) || (result.error === undefined ? "" : String(result.error.message)),
      exitCode: result.status ?? -1,
      timedOut: (result.error as NodeJS.ErrnoException | undefined)?.code === "ETIMEDOUT",
    };
  } finally {
    closeSync(outFd);
    closeSync(errFd);
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Asynchronous variant: same trick, plus a whole-tree kill on timeout. */
export function capture(file: string, args: string[], options: CaptureOptions = {}): Promise<CaptureResult> {
  const { dir, out, err } = scratch("async");
  const outFd = openSync(out, "w");
  const errFd = openSync(err, "w");
  const timeoutMs = options.timeoutMs ?? 60_000;

  return new Promise<CaptureResult>((resolve) => {
    let timedOut = false;
    let child;
    try {
      // The child inherits duplicates of these handles; the parent's copies are
      // closed immediately below so the files reach EOF when the child exits.
      child = spawn(file, args, {
        cwd: options.cwd,
        env: options.env ?? { ...process.env, ...TOOL_ENV },
        stdio: ["ignore", outFd, errFd],
        windowsHide: true,
      });
    } catch (error) {
      closeSync(outFd);
      closeSync(errFd);
      rmSync(dir, { recursive: true, force: true });
      resolve({ stdout: "", stderr: String((error as Error).message), exitCode: -1, timedOut: false });
      return;
    }
    closeSync(outFd);
    closeSync(errFd);

    // execa's own timeout kills only the direct child; on Windows the
    // grandchildren keep the handles open and `await` never settles (#49).
    const treeKill = setTimeout(() => {
      timedOut = true;
      killProcessTree(child.pid);
    }, timeoutMs);

    const finish = (exitCode: number, spawnError?: Error): void => {
      clearTimeout(treeKill);
      const result: CaptureResult = {
        stdout: safeRead(out),
        stderr: safeRead(err) || (spawnError === undefined ? "" : spawnError.message),
        exitCode,
        timedOut,
      };
      rmSync(dir, { recursive: true, force: true });
      resolve(result);
    };
    child.on("error", (error) => finish(-1, error));
    child.on("close", (code) => finish(code ?? -1));
  });
}

function safeRead(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return "";
  }
}
