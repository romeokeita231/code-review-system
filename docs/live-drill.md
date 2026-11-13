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

### The `ocr` pin, and why it is a commit and not a version

`ocr` ships a self-updater: each invocation spawns `scripts/update.js`, which runs
`npm i -g @alibaba-group/open-code-review@latest` when a newer release exists. That is how
the binary moved from the pinned `04deca6` to `4236c87` between two sessions while the
config kept claiming the pin. The gate caught it; the updater was the hole.

Two changes, both structural:

- `TOOL_ENV = { OCR_NO_UPDATE: "1" }` is passed to every process this system spawns
  (`src/config/index.ts`, used by `src/l3/semgrep.ts`, the instrument probe and the drill),
  and the user-level variable is set as well. A measurement may only change tool when a
  human changes it.
- The pin is the **build commit**. `v1.13.7` was tagged at `b1dcffb`, so matching a release
  number would accept the wrong binary; `ocr --version` prints
  `open-code-review v1.13.6 (04deca6)`, and that parenthesised token is what the config
  carries.

`04deca6` is not a release tag, so it is rebuilt rather than downloaded (`make build`
semantics at that commit; recipe and sha256 in `docs/toolchain.md`). A drifted binary makes
every AOR number unquotable — including the T1/T2 budget measurements of #22 — until it is
re-pinned, and "unpinned" is not a label a run may carry: the eval happens once, so a
number taken on a replaced binary can never be reproduced on the pinned one.

The old `dataset detectability` check is **gone**, not relaxed: it scanned planned
*eval* positives with the pinned ruleset, which is a detector output on eval before the
freeze. It also measured ds-1. Its replacement is the fit-run coverage matrix
(`npm run record:fit`), which only ever touches fit rows.

### Gates: three have no bypass

`--allow-degraded` used to be one switch for the whole preflight, which meant "waive
anything" — the same shape as the deleted `--allow-short`. It is now a per-gate whitelist,
and three gates are not on it:

| gate | why it can never be waived |
| --- | --- |
| `ocr pin` | instrument identity: a drifted binary makes every number unreproducible |
| `calibration artifact` | dataset identity: a stale artifact applies thresholds fitted on another class set |
| `DEEPSEEK_API_KEY` | measurement feasibility: without it no live session exists to measure |
| `plugin bundle` | shipped identity: the rows are written by `dist/plugin.js`, so a bundle older than `src/` measures the previous system, and its rows are in a shape `evaluate` refuses — discovered after the eval is spent |


```bash
npx tsx scripts/live-drill.ts --stage prepare --out runs/live/eval-ds-2.0.0-<stamp> \
  --allow-degraded=<gate>[,<gate>]
```

The bare flag is an error, an unknown name is an error, and waiving one of the three above
is an error. Waived gates are printed as `DEGRADED (waived by name)` and recorded in the
run's `run.json`.

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

`plan: ...` and `coverage declared: ...` print on every stage. The plan always reports
**available vs staged**: `--allow-short` is gone, because 20 was never a fact about the
data — the run proceeds, and line 1 records the recall face as `insufficient_n` with its
measured rate instead of refusing to measure.

The evaluator applies the same rule to the rows it reads (`line1 denominator by class`
at the end of `report.md`), so a class the ruleset cannot see gets its own row marked
`outside line1` with its declared rule count.

## Line 1's two units, two gates (2026-11-13)

`n >= 20` never named its unit. Recall counts **samples** (did the write get caught),
precision counts **findings** (does each surfaced finding sit on a real defect). One
number cannot gate both:

| face | unit | n | gate | when short |
| --- | --- | --- | --- | --- |
| recall | sample | `n` (covered, scannable eval positives) | `>= 20` | `insufficient_n`, still reports k/n + Wilson 95% |
| precision | finding | merged findings on eval rows | `>= 20` | `insufficient_n`, still reports tp/n |

`report.md` prints both rows plus `available` / `staged`: `ds-2` has 11 gateable eval
positives, the per-class cap stages 10, so the shortfall is visible and is **not** a
detector result. A rate reported under `insufficient_n` is marked `descriptive, not
gated` — "cannot be gated" and "was not measured" are different claims.

## Preregistered predictions (v1 2026-11-13T11:49:57+08:00, revised 2026-11-13T13:05:00+08:00)

Machine-readable copy with both revisions: `artifacts/preregistration.json`. The revisions
below are **clarifications of the denominator and of degenerate branches**, made before any
eval output existed; no threshold and no direction of a claim was relaxed.

| id | v2 (current) | what v1 said and why it changed |
| --- | --- | --- |
| P1 | semgrep's hits ⊆ CWE-089, `k <= 2` on the **staged attempted set (`n = 10`)** | v1 wrote `k <= 2/11`. 11 is `available` (gateable eval positives), 10 is `staged`: the cap stages 10, so 11 was a denominator the run could not have. Restating it on the staged set keeps the bound where the measurement is. |
| P2 | if semgrep `k >= 1`: AOR sample recall `>= 3x` semgrep recall. **If `k = 0`: the ratio claim is void and P2 degenerates to an absolute lower bound, AOR recall `>= 0.55`** | a ratio with a zero denominator is not a prediction. CWE-089 has only one eval sample, so `k = 0` is a live possibility, and it now has a stated consequence instead of silently "passing". |
| P3 | `semgrep ∩ AOR ⊆ semgrep hits`, `|intersection| <= 2` — **degraded when `k = 0`** | with `k = 0` the intersection is empty by construction, so the bound holds for free. That is a vacuous pass, and it must be *labelled* as one rather than counted. |
| P4 | the `AOR-only` cell's TP rate is below the `both` cell's | unchanged: the contingency table `{semgrep-only, AOR-only, both}` is read off `findings_merged[].sources`, no threshold involved. |

The contingency table replaces the old "warn needs a probability" framing: warn now fires on
a zero-parameter structured decision (`severity >= warn`, `threshold_source:
"severity_policy"`), so lines 3–5 are measurable without a fitted warn point. Any path that
still claims a probability keeps propagating `unfittable`.

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
exclusions cannot hide each other. `language_coverage` prints alongside — authoritative
counts on `ds-2`: **all rows 29 typescript / 6 javascript, positives 20 / 6, eval positives
11 / 3** — and the paper's capability claim is limited to Python + TypeScript. Adding a
JavaScript subset later means re-measuring the recall: those are new rule bodies, not an
inherited number.

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
# 1. mint the one named run directory (dataset version + UTC stamp)
npx tsx scripts/live-drill.ts --stage prepare --new-run
# 2..4. the same directory for the rest of the stages
npx tsx scripts/live-drill.ts --stage run     --out runs/live/eval-ds-2.0.0-<stamp>
npx tsx scripts/live-drill.ts --stage collect --out runs/live/eval-ds-2.0.0-<stamp>
npx tsx scripts/live-drill.ts --stage evaluate --out runs/live/eval-ds-2.0.0-<stamp>
```

Stages: `check` → `prepare` → `run` → `collect` → `evaluate` (`--stage <name>` runs one).
`prepare` stages the eval positives the ruleset can gate (10 of 11 on `ds-2`) + **every
defect-free low-risk row** (9 on `ds-2`: 8 edits + 1 create) + one dependency-hallucination
probe per baseline (`B4`, `B4g`) in `<run>/scratch/<baseline>`, each its own git repo with
the pinned rulesets copied in. `run` drives one headless DSH session per baseline (write
pass, then a correction pass on the same session id), `collect` maps plugin `ReviewRow`s to
the evaluator shape, and `evaluate` writes
`artifacts/acceptance/{report.md,verdict.md,verdict.json}`.

### The run directory is part of the measurement

Every non-`check` stage refuses a directory whose leaf is not
`eval-<dataset version>-<yyyyMMddTHHmmss>` (or `smoke-...`), and `collect`/`evaluate` refuse
a directory whose `run.json` names another dataset. `run.json` records the dataset version,
the config hash, the frozen pin, the plan shape and the waived gates. This is the same rule
as instrument identity, applied to the dataset: a consumer that cannot check identity will
eventually mix two measurements. The ds-1 staging that used to sit in `runs/live` beside the
ds-2 run is exactly the entry point that rule closes.

`plan.controls` stages nothing extra on `ds-2`; it remains for datasets whose negatives are
`high` risk. Low-risk rows that carry a defect are **not** staged (`3` of them on `ds-2`,
all fit-split positives): they would either inflate precision or put a vulnerable file into
line 4's pairs. With no defect-free row at all the evaluator reports `precision: na` and
fails line 1 instead of printing a vacuous `tp/tp = 1.0`.

Every injected message carries its provenance: `via=<sources>[/agree]/sev=<source>` sits
right after the anchor, so clipping cannot remove it.

## Two Windows-only traps

1. **Never launch `dsh` through the `dsh.ps1` shim from a sandboxed shell.** That
   process tree cannot open the certificate store, and `semgrep-core` dies in its CA
   bootstrap (`CertOpenSystemStore returned NULL`) before matching any rule. The drill
   invokes `node .../@deepseek-ai/dsh/lib/bin.js` directly for this reason.
2. **Ruleset paths in `configs/*.json` are repo-relative.** The adapter resolves them
   against its root, so a scratch repo needs the same tree; `prepare` copies the
   snapshots. Without it every scan reports `rules_missing`.

## Known blockers (2026-11-13, after the ds-2 re-encode)

- **`DEEPSEEK_API_KEY` is the only red gate.** The `ocr` pin is green again:
  `open-code-review v1.13.6 (04deca6)`, rebuilt from the pinned commit and protected by
  `OCR_NO_UPDATE=1`. Everything else in the preflight passes, including `plugin bundle`
  (`dist/plugin.js` rebuilt after the `instrument` change).
- **A row now names the binary that answered.** `ReviewRow.instrument` carries
  `{semgrep, ocr}` with `{name, version, commit, source}` next to the declared `toolchain`;
  `evaluate` **refuses** (not warns) when a row's identity is missing, `declared` instead of
  `observed`, mixed across rows, or different from `configs/b4.json`. This is the third
  occurrence of "the artefact did not carry its own instrument" (`ts_all` vs `ts_dedup`,
  `semgrep scan` vs `semgrep-core`, `ocr` drift), so it is now a schema field and a refusal
  rather than a checklist item.
- **Warn is a policy, not a probability.** `artifacts/calibration.json` carries
  `thresholds.status: "unfittable"` (`fit_negatives = 0`, 4 findings). Any path that
  claims a probability still propagates `unfittable` and refuses to invent a constant;
  the warn face instead fires on the sources' own declared severity (semgrep
  WARNING/ERROR, AOR P2/P1) and records `threshold_source: "severity_policy"`. That is
  what makes lines 3–5 measurable again without a fitted warn point. The statement "warn
  is uncalibrated" must follow every number taken from it.
- **Line 1's recall face is `insufficient_n`, not a failure to run.** 14 eval positives,
  11 TypeScript (the drill stages one language), `POSITIVE_CAP_PER_CLASS = 4` over 5
  covered classes: 10 staged of 11 available, gate 20. The measured rate and its Wilson
  interval are printed as `descriptive, not gated`; `--allow-short` no longer exists.
- **Line 4's pool exists now.** 9 defect-free low-risk rows (8 edits + 1 create);
  `low_risk_pool` fails the dataset gate below 8.
- **The create path is exercised once, not measured.** `ts-cwe022-9010` is a `create`
  (`before = ""`, content = the vetted text of `ts-cwe022-9001`). It proves the create
  branch is not dead code; `n = 1` and no precision claim is made for it. `event_kind` is
  derived from `before === ""`, and the dataset gate fails if either kind disappears from
  the pool.
- **JavaScript is `out_of_scope`.** 6 of the 35 rows are `.js`; the shipped config has no
  JavaScript subset and no `sMax['javascript']`, so they are never scanned. This is the
  second appearance of "declared != shipped" (the first was `ts_all` vs `ts_dedup`): the
  rules table says what exists, the config says what runs, and nothing forces agreement.
  A build-time assertion is the follow-up ticket.
- **Replay recordings are real for fit only.** `tests/fixtures/replay/*` now hold actual
  `semgrep scan` envelopes for the 12 fit rows; the eval recording does not exist yet,
  and `scripts/record-dataset.ts --split eval` refuses to run without `--allow-eval`.
