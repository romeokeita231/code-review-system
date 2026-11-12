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
| Calibration artifact matches this dataset and ruleset | same check; `thresholds.status: "unfittable"` is expected on `ds-2` (see below) |
| Every staged row's language has a shipped subset | python + typescript only; JavaScript rows are `out_of_scope` |

Run the gate first — it exists so a run fails for the right reason:

```bash
npx tsx scripts/live-drill.ts --stage check
```

One failure in that gate is expected:

- `ocr pin` — the config claims `04deca6`, the installed binary reports another
  commit. Re-pin (`npm i -g @alibaba-group/open-code-review@<pin>`) before quoting any
  AOR number, including the T1/T2 budget experiments.

The old `dataset detectability` check is **gone**, not relaxed: it scanned planned
*eval* positives with the pinned ruleset, which is a detector output on eval before the
freeze. It also measured ds-1. Its replacement is the fit-run coverage matrix
(`npm run record:fit`), which only ever touches fit rows.

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

## Two denominators, one gate: `out_of_scope` vs `timeout`

The shipped config scans Python and TypeScript. `sMax` has no `javascript` entry and the
subset list has no JavaScript subset, so a `.js` row is **never attempted** — the source
returns `degraded / language_unsupported`. That is a different fact from a failure:

| state | meaning | in the recall denominator |
| --- | --- | --- |
| `timeout` | attempted, failed | **yes, as a miss** |
| `language_unsupported` | never attempted | **no** — reported as `out_of_scope` |
| `insufficient_n` | attempted, too few rows | pooled only; no per-class claim |

The fit matrix (`npm run record:fit`) and the evaluator (`scripts/acceptance.ts`) both
print two denominators — all rows and attempted rows — and gate on the attempted one.
`line1` also carries `n + excluded + out_of_scope = eval positives`, so the three
exclusions cannot hide each other. `language_coverage` prints alongside
(`ds-2`: 0 python / 27 typescript / 6 javascript), and the paper's capability claim is
limited to Python + TypeScript. Adding a JavaScript subset later means re-measuring the
recall: those are new rule bodies, not an inherited number.

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

### Latency: the 1.2 s criterion is retired

`research/semgrep-bench/ts_block_bench.json` (n=10 real `.ts` files, 5.0–48.0 KiB,
`ts_dedup.yaml` sha256 `42e5be0c…`):

| Invocation | p50 | p95 | p99 |
| --- | --- | --- | --- |
| `semgrep-core -rules … -targets … -json` | 343.0 ms | 574.3 ms | 651.3 ms |
| `semgrep scan --config …` (**shipped**: what `src/l3/semgrep.ts` spawns) | 3139.2 ms | 3240.3 ms | 3254.9 ms |

The 1.2 s criterion described the first shape while the implementation makes the second,
so the criterion is **withdrawn**, not "missed". The fit run (ds-2, 12 rows) puts the
shipped shape at 3.3–4.7 s per scan and one 4.3 KB file at 5.9 s: the 5 s
`semgrepKillMs` / `callMs` pair is not a safe upper bound on ordinary hardware, not
merely an inaccurate estimate. What gets reported instead is the shipped shape's
p50/p95/p99 **plus both budgets** (kill and call), always with the invocation shape
attached. A latency number without its shape is not evidence; ADR 0007 now states that
as a general rule.

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
first, and line 4 pairs B4 against B4g on them. Line 1's false-positive denominator is a
separate list: `plan.controls` stages the defect-free rows regardless of `risk_level`
(`ds-2`: 7), because §9's `low` describes the *change*, not defect-freeness. With no
control row at all the evaluator reports `precision: na` and fails line 1 instead of
printing a vacuous `tp/tp = 1.0`.

## Two Windows-only traps

1. **Never launch `dsh` through the `dsh.ps1` shim from a sandboxed shell.** That
   process tree cannot open the certificate store, and `semgrep-core` dies in its CA
   bootstrap (`CertOpenSystemStore returned NULL`) before matching any rule. The drill
   invokes `node .../@deepseek-ai/dsh/lib/bin.js` directly for this reason.
2. **Ruleset paths in `configs/*.json` are repo-relative.** The adapter resolves them
   against its root, so a scratch repo needs the same tree; `prepare` copies the
   snapshots. Without it every scan reports `rules_missing`.

## Known blockers (2026-11-12, after the ds-2 freeze)

- **`ocr` self-updates** past the pinned `04deca6` (observed v1.13.8 / `4236c87`); the
  `ocr pin` gate fails until it is re-pinned. No AOR number may be quoted meanwhile.
- **Warn is unfittable.** `artifacts/calibration.json` carries
  `thresholds.status: "unfittable"` (`fit_negatives = 0`, 4 findings), and a consumer
  that needs a threshold propagates that state rather than substituting a constant. Line
  1's block facet does not depend on it — certified rules gate the block face — but lines
  3–5 drive `[CRS-WARN]` and therefore cannot be measured until a warn operating point
  exists. That is the recorded cost of measuring precision once: fitting a warn point
  requires negatives inside fit, which would end the blind measurement.
- **Line 1 cannot reach `n >= 20` on `ds-2`.** The eval split has 14 positives, 11 of them
  TypeScript (the drill stages one language), and `POSITIVE_CAP_PER_CLASS = 4` spreads
  those over 5 covered classes: 10 are staged. `evaluateAcceptance` requires `n >= 20`, so
  the gate fails before recall is considered. That is a dataset-size fact, not a detector
  result; `--allow-short` remains wiring-only.
- **Line 4 has no defect-free pairing pool.** 11 of 33 rows are `risk_level: low`
  (079/798 with changes <=30 lines), but every one of them is a positive, so the 3 staged
  low-risk slots are defective and the B4/B4g pairs are not clean. Line 4 wants 8
  defect-free low-risk samples; `ds-2` has none.
- **JavaScript is `out_of_scope`.** 6 of the 33 rows are `.js`; the shipped config has no
  JavaScript subset and no `sMax['javascript']`, so they are never scanned. This is the
  second appearance of "declared != shipped" (the first was `ts_all` vs `ts_dedup`): the
  rules table says what exists, the config says what runs, and nothing forces agreement.
  A build-time assertion is the follow-up ticket.
- **Replay recordings are real for fit only.** `tests/fixtures/replay/*` now hold actual
  `semgrep scan` envelopes for the 12 fit rows; the eval recording does not exist yet,
  and `scripts/record-dataset.ts --split eval` refuses to run without `--allow-eval`.
