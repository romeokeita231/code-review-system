# Live drill (acceptance lines 1–5)

This is the operator runbook for ticket #41. The replay track (`npm run dataset:*`,
`scripts/calibrate.ts`) is separate: `mode=live` rows may only come from a real DSH
session with the plugin mounted.

## Prerequisites

| What | Check |
| --- | --- |
| CRS plugin is a Cordis bundle (`dist/plugin.js`, `cordis.patch.yml`) | `dsh --profile crs-live --dump-config` shows the `code-review-system` row |
| Isolated DSH profile | `dsh crs-live --from-default-profile headless` then `dsh plugin --profile crs-live add <repo>` |
| `DEEPSEEK_API_KEY` in the environment | `scripts/live-drill.ts --stage check` |
| semgrep 1.184.0, code-review-graph 2.3.9, ocr at the pinned commit | same check (`ocr pin` fails when the binary self-updated) |
| Planned positives are actually matched by the pinned TS ruleset | same check (`dataset detectability`) |

Run the gate first — it exists so a run fails for the right reason:

```bash
npx tsx scripts/live-drill.ts --stage check
```

Two failures in that gate are expected until the dataset is rebuilt:

- `dataset detectability` — the pinned `ts_dedup.yaml` matches 0 of the planned
  positives, so line 1's mechanical-block recall cannot reach 0.70.
- `ocr pin` — the config claims `04deca6`, the installed binary reports another
  commit. Re-pin (`npm i -g @alibaba-group/open-code-review@<pin>`) before quoting any
  AOR number, including the T1/T2 budget experiments.

## How the 20 positives are chosen

Selection happens **before** any scan and never reads `expected_detectable_by`: the
annotation spec (#7 §6) marks that field as a non-truth hint that must not enter a
metric, and using it as the selector let the dataset define its own denominator.

1. `split=eval` and `defects` non-empty (pair-safe variants have none, so they fall out).
2. Order by `sha256(sample_id)` — not `localeCompare`, whose class prefix clusters the
   sample set (`s-CWE-22-*` then `s-CWE-502-*` and nothing else).
3. Round-robin across classes with a **cap of 4 per class**, so ≥5 classes are in the
   set; the cap is what stops one class from becoming the whole drill.
4. A class is *covered* when `research/semgrep-bench/snapshot/rules_table.json`
   declares at least one rule for it and for `typescript`. Everything else is listed
   in `coverage.uncovered` and printed as a warning — never sliced away silently.

`plan: ...` and `coverage declared: ...` print on every stage. If the plan cannot reach
20 positives, `--stage run` refuses unless `--allow-short` is passed; that flag is for
wiring tests only.

The evaluator applies the same rule to the rows it reads (`line1 denominator by class`
at the end of `report.md`), so a class the ruleset cannot see gets its own row marked
`outside line1` with its declared rule count.

## Line 1's block facet is Python-only (design conclusion, 2026-11-13)

Line 1 splits into a detectability facet and a *mechanical block* facet. Block can only
happen at `pre-execute`, on a fact the pinned ruleset certified as a block rule
(`src/l3/semgrep.ts` marks a finding `certified` iff its id is in the subset's
`blockRules`). `py-block` has 6 certified ids; `ts-dedup` has none, so **every TS
finding is `certified: false`** and no TS sample can ever be blocked. Reporting a TS
block precision/recall would be a 0/0 value of the same kind as the old `tp/tp = 1.0`.

Extending the block guarantee to TS was gated on three conjunctive criteria (issue #41,
step 0). The first one already has an empty domain:

| Criterion | Result |
| --- | --- |
| (a) same `upstream_id` family as a certified py rule (a language variant of the same rule) | **0 of 95** TS-applicable rules |
| (b) zero hits on negatives | not evaluated — no candidate |
| (c) `criterion_iii` per-rule hit record | not evaluated — no candidate |

Criterion (a) is empty because all six certified rules are Python-only sinks
(`os.system`, `subprocess`, a DB cursor, `open()`): the javascript/typescript rule
directories contain no variant of any of those ids. Cross-language twins *do* exist in
the ruleset (`tainted-sql-string`, `raw-html-format`, `mysql-sqli`,
`tainted-html-response`, `tainted-html-string`) — they are simply not in the certified
set. So the block guarantee cannot be extended by transcription; it would need a fresh
criterion i/ii/iii certification, which is a spec decision, not a measurement.

Latency was not the blocker. `research/semgrep-bench/ts_block_bench.json` (n=10 real
`.ts` files, 5.0–48.0 KiB, `ts_dedup.yaml` sha256 `42e5be0c…`):

| Invocation | p50 | p95 | p99 | vs 1.2 s |
| --- | --- | --- | --- | --- |
| `semgrep-core -rules … -targets … -json` (the shape the 1.2 s criterion was certified against) | 343.0 ms | 574.3 ms | 651.3 ms | pass |
| `semgrep scan --config …` (**what `src/l3/semgrep.ts` actually spawns**) | 3139.2 ms | 3240.3 ms | 3254.9 ms | fail |

The second row is worth stating in the paper: the pre stage's 1.2 s budget describes a
`semgrep-core` invocation the implementation does not make. The full CLI still lands
inside `timeoutsMs.callMs` (5000 ms), so facts do arrive in time for `pre-execute`; but
a 1.2 s number may only be quoted with the invocation shape attached.

How to report it: line 1's block facet goes out as `na` with `n=0 / k=<positives>`, and
the verdict text says the mechanical block is Python-only. Do not substitute a
detectability number for it.

## Run

```bash
npx tsx scripts/live-drill.ts --stage all
```

Stages: `check` → `prepare` → `run` → `collect` → `evaluate` (`--stage <name>` runs one).
`prepare` stages 20 eval positives + 8 low-risk samples + one dependency-hallucination
probe per baseline (`B4`, `B4g`) in `runs/live/scratch/<baseline>`, each its own git
repo with the pinned rulesets copied in. `run` drives one headless DSH session per
baseline (write pass, then a correction pass on the same session id), `collect` maps
plugin `ReviewRow`s to the evaluator shape, and `evaluate` writes
`artifacts/acceptance/{report.md,verdict.md,verdict.json}`.

`--allow-degraded` skips the gate for a wiring-only run; it cannot produce a passing
verdict.

The 8 low-risk slots are taken from defect-free (`defects: []`) `risk_level=low` rows
first. That is deliberate: line 4 pairs B4 against B4g on them, and line 1 needs at
least one false-positive denominator. With no defect-free row at all, the evaluator
reports `precision: na` and fails line 1 instead of printing a vacuous `tp/tp = 1.0`.

## Two Windows-only traps

1. **Never launch `dsh` through the `dsh.ps1` shim from a sandboxed shell.** That
   process tree cannot open the certificate store, and `semgrep-core` dies in its CA
   bootstrap (`CertOpenSystemStore returned NULL`) before matching any rule. The drill
   invokes `node .../@deepseek-ai/dsh/lib/bin.js` directly for this reason.
2. **Ruleset paths in `configs/*.json` are repo-relative.** The adapter resolves them
   against its root, so a scratch repo needs the same tree; `prepare` copies the
   snapshots. Without it every scan reports `rules_missing`.

## Known blockers (2026-11-12)

- The self-built dataset is **not semgrep-detectable**: 0 of the first 5 planned
  positives match the pinned `ts_dedup.yaml`. `expected_detectable_by: ["semgrep"]`
  in the manifest is therefore unbacked, and line 1 cannot reach recall ≥ 0.70.
- The dataset is **not spec-conformant** (`npx tsx scripts/verify-dataset.ts
  --conformance`: 2649 violations across 5 rules — field names, `sample_id` pattern,
  risk levels, CWE-502 where §6 asks for CWE-918, 60 rows per class instead of a 3:2
  split). `verifyDataset` passes because it validates the manifest against itself.
- All 210 pair-safe "variants" are **no-op writes** (`before === after`), so they cannot
  serve as a real precision denominator until the dataset is rebuilt.
- The replay fixtures under `tests/fixtures/replay/*/semgrep.json` are synthetic
  (`evidence: "recorded semgrep hit #1"`), so replay recall/precision are placeholders,
  not measurements.
- `ocr` self-updates past the pinned `04deca6` (observed v1.13.8 / `4236c87`); the
  `ocr pin` gate fails until it is re-pinned.
