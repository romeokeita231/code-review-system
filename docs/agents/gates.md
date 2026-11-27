# Gates

Six checks added by the 2026-11-27 retro, plus the replay harness that keeps them honest. Each one exists because a run completed, produced a complete report, and a source behind that report was already gone.

Run them from the repo root; all of them work in the **default sandbox** (no elevated shell needed):

```bash
npm run gate:all        # replay + hashes + degeneration; the three that must be green before a commit
npm run gate:replay     # feeds every check its incident; all 25 must land on the expected state
npm run gate:hashes     # does every recorded sha256 describe the tracked form it claims?
npm run gate:machine    # is this machine the one the frozen floor describes?
npm run gate:residue    # is something still running that a probe started?
npm run gate:degeneration  # do the failures that print a number instead of throwing still pass?
npm run env:probe       # not a gate: what this machine can do, in one table
```

`gate:all` is enforced by `.github/workflows/gates.yml` alongside `typecheck`, `test` and `check:secrets`. `gate:machine` is deliberately **not** in CI: it measures the host it runs on, so on a shared runner it would be red or green for reasons unrelated to the commit. It belongs in preflight, where the machine is the one about to run.

## Why `node scripts/run.mjs`, not `tsx`

`tsx`, `vitest` and every `esbuild` consumer start a service worker over an IPC pipe. Piped stdio is refused in the default sandbox:

```
Error: spawn EPERM   errno -4048   syscall: 'spawn'
  at startSyncServiceWorker (esbuild/lib/main.js)
```

So `scripts/run.mjs` emits with `tsc` (pure file I/O) into `.tmp/run/` and runs the output with plain `node`. The same boundary hits anything that captures a child's output — `execFileSync`, `spawnSync(..., {encoding})`, `execa` — all `EPERM`. `scripts/capture.ts` redirects the child's stdout to a **real file handle** instead of a pipe, which works. Use it for anything that shells out from a gate.

`npm test` (`vitest`) and the `tsx`-based tooling (`drill`, `calibrate`, `report`, `check:secrets`, …) still need a non-sandbox shell. `gate:degeneration` lists them as `na` on every run so the gap stays visible.

## What each gate refuses

| gate | refuses when | the incident |
| --- | --- | --- |
| `gate:machine` | this machine needs a larger `impact` floor than `frozen.budgets.crg_query_ms`, or the two pre-path floors no longer fit `callMs` | 2026-11-19/20: same commits, same `code-review-graph` 2.3.9, p99 662 → 2672 ms. The gate compared config against a frozen value; the machine was in no gate at all |
| `gate:machine` | `semgrep` fails or hangs, or `semgrep_kill_ms` has no distribution behind it | a floor from one observation cannot tell "warm 650 ms" from "hangs forever" |
| `gate:residue` | an instrument process is old **and** has burned CPU | a `pysemgrep --version` owned a core for five hours and nothing looked |
| `gate:residue` | the process table cannot be enumerated | "could not look" must never render as "clean" |
| `wiring:check` / `gate:*` | the script starts through a spawning transpiler | the replacement for `--allow-degraded` exited 1 with `spawn EPERM` |
| `gate:degeneration` | the archived `report.md` no longer recomputes to the same bytes | the table is a recomputation; silent evaluator drift makes it describe a program that no longer exists |
| `gate:hashes` | a recorded hash or size does not describe the tracked form it claims (index, not disk) | first CI run: 9 `SemgrepSource` tests degraded with `rules_sha256`; the pin described a CRLF working copy that no checkout reproduces |
| `preflight` (in `drill`) | the worktree is dirty, a run has no `repo.commit`, line 4 has no row source | "which code did that run measure" had no answer |

## Content pins and byte pins

A recorded `sha256` is a claim about something. Which something is not obvious, and getting it wrong made the scanner go quiet twice, so every record now declares one of two kinds (`scripts/hash-agreement.ts`):

- **content** — the pin is about what the file says. Take it with `contentSha256` (`src/config/index.ts`), which folds CRLF to LF first. Rule pins live here: `SemgrepSource` will not scan unless the pin matches, and the rules bench measured the rules, not a checkout.
- **bytes** — the pin is about an emitted artifact. Take it with plain `sha256`. `research/semgrep-bench/snapshot/manifest.json` is the build's own description of what it wrote; normalising it would let the manifest lie about the file it produced.

The rule is: **a pin is EOL-independent only if both sides fold.** A pin taken over a checkout's bytes is a function of that checkout's line-ending policy — the same rule set is `612934ee…` under `core.autocrlf=true` and `ab8998b6…` on an LF tree — and `git status` reports neither, because the index agrees with `HEAD` while the working copy does not. That is how the first CI run this repository ever had came back with nine `SemgrepSource` tests degraded and the report saying "no findings".

`research/**`, `artifacts/**`, `datasets/**` and `schemas/**` are `-text` in `.gitattributes`, so git never rewrites them and a `bytes` pin is reproducible everywhere. A `content` pin needs no such help — prefer one, unless the value really is a claim about written bytes.

## `na` is not `0`

Every gate row is `pass`, `fail`, or `na`. `na` means *not looked*. It renders `na` and never counts as a pass in a summary — #50's rule, applied to the gates themselves rather than only to the report.

## Keeping a check honest

`gate:replay` holds one fixture per incident: the incident's own inputs, with the expected state written down and the source cited. A control fixture sits beside each one and must stay green, because a check that fires on everything gets disabled.

If a check is weakened, its fixture goes green where it must be red and `gate:replay` exits 1. That is the difference between this and a paragraph saying "be careful next time".
