/**
 * Which code did this run measure?
 *
 * Retro 2026-11-27, friction ⑤.
 *
 * `runs/live/eval-ds-2.0.0-20261114T132232/run.json` records
 * `frozen_instruments` (semgrep version, `ocr` commit, the AOR model) and
 * nothing about this repository. So the one question a reader will always ask -
 * *which revision of the thing under test produced these rows* - could only be
 * answered from a directory timestamp. That is why the retro's own window had to
 * be expressed as `--since <timestamp>` instead of a commit range, and why four
 * later commits touching `src/` and `configs/` cannot be attributed to the
 * archived numbers either way.
 *
 * Two separate failures live here, and they get two separate gates:
 *
 *   1. A *new* run must record the commit it ran on. Absence is not a gap to
 *      fill in later; it is a run that cannot be quoted.
 *   2. A run staged from a *dirty* tree measures code that does not exist in any
 *      commit. That was possible until now, and it is worse than a missing
 *      field, because the commit that does get recorded looks authoritative.
 *
 * Old runs keep reading as `na`. #50's rule - never retroactively rewrite a
 * published number - applies to run metadata too: the 2026-11-14 run did not
 * record its commit, and inventing one for it would be the same error as
 * counting "not measured" as "corrected".
 */
import type { GateVerdict } from "./shared.js";
import { captureSync } from "./capture.js";

export interface RepoIdentity {
  /** Full SHA. Abbreviated would collide across forks of the same history. */
  commit: string;
  branch: string;
  dirty: boolean;
  /** Count, because "dirty" alone does not say whether one file or forty moved. */
  dirty_files: number;
  /** When the observation was taken; a commit with no clock is half an identity. */
  at: string;
}

/**
 * Runs staged before this instant have no `repo` field and are not expected to.
 * Chosen as the day the retro landed, so the boundary is a fact about when the
 * recording started rather than a claim about what an old run measured.
 */
export const REPO_RECORDING_SINCE = "2026-11-27T00:00:00+08:00";

function git(cwd: string, args: string[]): string {
  // File-redirected capture, not `execFileSync`: a piped child is spawn EPERM in
  // the default sandbox, and "which commit" must be answerable there too.
  const result = captureSync("git", args, { cwd, timeoutMs: 30_000 });
  if (result.exitCode !== 0) {
    throw new Error(`git ${args.join(" ")} failed in ${cwd}: ${result.stderr.trim().slice(0, 200)}`);
  }
  return result.stdout.trim();
}

/** Observe, never assume: a commit typed into a config is a claim. */
export function readRepoIdentity(cwd = process.cwd()): RepoIdentity {
  const commit = git(cwd, ["rev-parse", "HEAD"]);
  const branch = git(cwd, ["rev-parse", "--abbrev-ref", "HEAD"]);
  const porcelain = git(cwd, ["status", "--porcelain"]);
  const lines = porcelain.length === 0 ? [] : porcelain.split("\n").filter((line) => line.trim().length > 0);
  return {
    commit,
    branch,
    dirty: lines.length > 0,
    dirty_files: lines.length,
    at: new Date().toISOString(),
  };
}

/**
 * Blocking preflight check: a one-shot measurement must not run on a tree whose
 * content is not a commit.
 */
export function judgeRepoClean(identity: RepoIdentity): GateVerdict {
  return {
    name: "repo clean",
    ok: !identity.dirty,
    detail: identity.dirty
      ? `${identity.dirty_files} uncommitted path(s) on ${identity.branch}: the rows would be ` +
        `about code that exists in no commit, and the commit recorded beside them would look ` +
        `authoritative anyway. Commit, or stage from a clean worktree`
      : `${identity.commit.slice(0, 12)} on ${identity.branch}, worktree clean`,
  };
}

export interface RunRepoRecord {
  created_at?: unknown;
  repo?: Partial<RepoIdentity> | null;
}

/**
 * Which commit did *this* run measure?
 *
 * `na` for a run staged before the field existed; red for a run staged after it
 * that still does not carry one, or that claims a clean run on a dirty tree.
 */
export function judgeRunRepo(manifest: RunRepoRecord): GateVerdict {
  const name = "run records its commit";
  const repo = manifest.repo ?? null;
  const createdAt = typeof manifest.created_at === "string" ? Date.parse(manifest.created_at) : NaN;
  const required = Number.isFinite(createdAt) ? createdAt >= Date.parse(REPO_RECORDING_SINCE) : true;

  if (repo === null || typeof repo.commit !== "string" || repo.commit.length === 0) {
    if (!required) {
      return {
        name,
        ok: true,
        na: true,
        detail:
          `na: staged ${String(manifest.created_at)} predates repo recording ` +
          `(${REPO_RECORDING_SINCE}); "which code did this measure" is unanswerable from the file ` +
          `and is not reconstructed after the fact`,
      };
    }
    return {
      name,
      ok: false,
      detail:
        `the manifest carries no repo.commit, and it was staged after recording ` +
        `${REPO_RECORDING_SINCE} began: the run cannot say which code it measured. Only a ` +
        `timestamp is left, which is what forced the retro's own window to be a --since range`,
    };
  }

  if (repo.dirty === true) {
    return {
      name,
      ok: false,
      detail:
        `${String(repo.commit).slice(0, 12)} was recorded with ${repo.dirty_files ?? "?"} ` +
        `uncommitted path(s): the rows measure content that no clone of that SHA contains`,
    };
  }

  return {
    name,
    ok: true,
    detail:
      `${String(repo.commit).slice(0, 12)} on ${repo.branch ?? "?"} at ` +
      `${repo.at ?? "?"}, worktree clean`,
  };
}
