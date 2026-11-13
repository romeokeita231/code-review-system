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

It then moved a **second** time at 12:56:59 — after the pin had been restored — because the
updater is spawned *detached* and the child from an earlier invocation landed minutes later,
with `OCR_NO_UPDATE=1` already in its environment. The lesson is the one that governs the
whole instrument chapter: **a pin is a property that has to be re-observed before every run,
not a state that is reached once.** But observation is not protection either: a check that
can only report the drift after the one blind run is spent protects nothing.

So the updater is gone from the filesystem, not disabled by a variable:

- `scripts/update.js` is renamed to `scripts/update.js.disabled` inside the installed
  `@alibaba-group/open-code-review` package. The launcher then spawns nothing — a file that
  is not there cannot be unset, raced, or inherited. `OCR_NO_UPDATE=1` stays as well
  (`TOOL_ENV`), because two independent mechanisms cost nothing.
- The `ocr updater` gate fails if the file comes back (a reinstall restores it), so the
  mechanism is checked rather than assumed.
- `run` takes `ocr --version` **and** the binary's sha256 before the first baseline and
  again after the last one, and writes both into `run.json.ocr_identity`. `evaluate` refuses
  to print a number when they differ (`instrument_drifted`), or when the closing observation
  is missing. The version line names the commit; the hash catches a rebuild that keeps the
  commit string.

Two more changes, both structural:

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

### Gates: nine have no bypass

`--allow-degraded` used to be one switch for the whole preflight, which meant "waive
anything" — the same shape as the deleted `--allow-short`. It is now a per-gate whitelist,
and these gates are not on it:

| gate | why it can never be waived |
| --- | --- |
| `ocr pin` | instrument identity: a drifted binary makes every number unreproducible |
| `ocr updater` | the mechanism behind the pin: the updater is removed from the package, and a gate that only *reports* a drift after the one blind run has been spent is not a protection |
| `calibration artifact` | dataset identity: a stale artifact applies thresholds fitted on another class set |
| `DEEPSEEK_API_KEY` | measurement feasibility: without it no live session exists to measure |
| `plugin bundle` | shipped identity: the rows are written by `dist/plugin.js`, so a bundle older than `src/` measures the previous system, and its rows are in a shape `evaluate` refuses — discovered after the eval is spent |
| `aor model` | the deepest instrument: `ocr`'s commit says which client asked, the served model says what answered, and P2/P4 read AOR's output |
| `frozen pin` | the pin and the config must agree; otherwise an edit to the config silently moves the goalposts |
| `crg budget` | `crgQueryMs` decides whether the triage layer answers at all: below the graph CLI's floor the query times out, the tier falls back to the static ladder, and every row is tier 0 without anything reporting a failure. The value is frozen with the latency table that produced it |
| `secret not tracked` | the repository is public; a key in a tracked file is a leak no `.gitignore` can undo |

The `plugin bundle` check is a **proxy**: it compares mtimes. A checkout or a copy moves a
timestamp without changing the artefact, and source edited back to its old text still looks
new — it fails red more often than green, which is the safe direction, so it is kept for
this round. `run.json` records `bundle_check: "mtime"`, and the check prints both
timestamps, so a false red is diagnosable in one line. The upgrade is a content hash
injected at build time, tracked separately ("upgrade the bundle check to a source-tree
hash").

### The model is part of the instrument

Pinning `ocr` by commit says which client asked the question. It does not say what
answered: the model is configured in `~/.opencodereview/config.json` (`deepseek-chat`) and
the service reports the model that actually served the request (`deepseek-flash`). A
server-side swap under a fixed configured id would leave every AOR number attached to a
ruler nobody recorded.

So `instrument.aor_model = { provider, id, params: { url, configured } }` is written on
every row:

- `id` is the **served** model, read from `ocr llm test` (`Model:` is `resp.Model` when the
  service sends one). This is the ruler.
- `params.configured` is what the client asked for. Recorded beside the answer so an alias
  is a visible fact rather than an assumption.
- `params.url` is the endpoint.

`evaluate` refuses to print a number when any of them differs from the frozen pin in
`artifacts/preregistration.json`. If a future build compiles the model in, the honest value
is still a statement — `bundled@<commit>` — because "fixed" has to be recorded too, or the
field goes empty and nobody can tell a fixed model from an unrecorded one.

### The one-shot lock

A second run that starts after the first result was seen is no longer blind, and nothing
about the artefact says so. The lock is mechanical, not a policy:

```bash
npx tsx scripts/live-drill.ts --stage prepare \
  --allow-eval=eval-ds-2.0.0-<stamp>
```

- `--allow-eval` **carries the run name**; the bare flag is an error. The name is the token,
  it decides the run directory, and it is written into `run.json`.
- `prepare` scans `runs/live` for an `eval-*` run with the same `dataset_version`. If one
  exists — completed or not — it refuses, unless the operator states why:
  `--archive-and-restart="<reason>"`. The old run is moved to `runs/archive/`, the reason is
  recorded in the new `run.json`, and the archive is what makes "we started over" auditable.
- Restaging over the same name is refused too: a half-run is still a run.

### Cost is estimated before staging, recorded during the run

`prepare` runs `ocr scan` once on a generated scratch module (never a dataset sample) and
reads `summary.total_tokens`. The estimate is `probe x 2` (AOR reviews a write twice: a
preview pass and the scan) `x rows x 1.5` (correction headroom). If it exceeds
`frozen.cost.ceiling_tokens` in the preregistration, the run is refused **before** anything
is staged or archived: aborting halfway leaves a half dataset and spends the blind run
anyway.

`run` records each row's wall clock and tokens as it goes and totals them into
`run.json.cost.actual`, but does not abort on cost: the money is already spent by then, and
stopping would only lose the measurement.

```bash
npx tsx scripts/live-drill.ts --stage prepare --allow-eval=<name> \
  --allow-degraded=<gate>[,<gate>]
```

The bare flag is an error, an unknown name is an error, and waiving one of the gates in
the table is an error. Waived gates are printed as `DEGRADED (waived by name)` and recorded
in the run's `run.json`.

`prepare` also prints a wall-clock estimate: `rows x (semgrepKillMs + crgQueryMs +
measured ocr probe)`, plus the graph builds measured at staging. Its AOR term is one 38-line
probe call, so the total is a floor for AOR time and a ceiling for everything else. The
number is recorded in `run.json.evidence.wall_clock_estimate` next to the components, so a
later reader can re-derive it instead of trusting it.

### The tier is a property of the repository, not of the change's size

`staticTier` reads one input: how many files the change event carries. The host's write tool
carries exactly one `file_path`, so a one-file change is tier 0 however large the file is,
and no amount of vulnerable code in it moves the tier. Measured on 2026-11-13 with the real
sources (`ts-cwe079-0001`, post event, 214 lines): `tier: 0`, `tier_source: "static"`,
`sources` = semgrep only.

`computeTier` reads something else: the blast radius the graph reports for that file. So the
drill stages **three clean importers per positive row** (`live/<id>/__importers__/n.ts`,
each a single `import "../<file>";`) and none for the negatives. The change event is still
one file — AOR still scans one file — but the repository now says that file has four
dependants, which is tier 1 under the *same* `tier0.filesMax = 3` boundary. Measured on the
staged tree: ten positives at `tier 1 via triage, files=4, nodes=3`; nine negatives at
`tier 0 via triage, files=1, nodes=0`; index build 1.0 s for B4 and
`"not_applicable"` for B4g — a baseline that built nothing is not a baseline that built in
0 ms (ADR-0008).

**Those importers are written by this project, and every row says so.** A reader who was not
told would take `files=4` for a blast radius the system discovered in a real repository. Each
staged row therefore carries `authored_context: true` and `authored_importers: 3` in
`run.json`, and `artifacts/staged-context.json` — a committed measurement, regenerated with
`npm run drill:context` — records what the *same* query answers on the pinned checkout, with
each file's bytes checked against the dataset's `origin.blob_sha` so the answer belongs to
the pinned revision. Measured 2026-11-13:

| positive | upstream file | importers upstream | tier unmodified |
| --- | --- | --- | --- |
| ts-cwe079-0004 | `track-result.component.ts` | 3 | 1 |
| ts-cwe022-0001 | `dataErasure.ts` | 3 | 1 |
| ts-cwe798-0001 | `lib/insecurity.ts` | 96 | 2 |
| ts-cwe918-0001 | `profileImageUrlUpload.ts` | 3 | 1 |
| ts-cwe094-0002 | `b2bOrder.ts` | 4 | 1 |
| ts-cwe079-0003 | `data-export.component.ts` | 3 | 1 |
| ts-cwe022-0002 | `fileServer.ts` | 4 | 1 |
| ts-cwe094-0004 | `lib/xml.ts` | 4 | 1 |
| ts-cwe079-0007 | `last-login-ip.component.ts` | 3 | 1 |
| ts-cwe079-0005 | `administration.component.ts` | 3 | 1 |

So **0 of the 10 positives would be tier 0 unmodified**: six of them already have exactly
three importers upstream, three have four, and `lib/insecurity.ts` has 96. The importers do
not manufacture a blast radius — they reproduce, in a twenty-file tree, what the repository
already says; and the tier-1 path is not an artefact of them.

The same table limits the claim in the other direction. **The nine negatives are tier 0 in
the staged subtree only**: upstream, 0 of 9 are tier 0 (route and component files with 3–5
dependants; the create row `ts-cwe022-9010` has no upstream counterpart at all). Line 4
therefore measures the tier-0 path on a subset that dropped the importers, not the share of
low-risk changes a real repository keeps below the boundary.

**That limit travels with the number.** Line 4's ratio is quotable on its own, and alone it
reads as "the ladder saved tokens on this corpus" — which the counterfactual contradicts. So
`acceptance.ts` prints `upstream_tier0=0/8` (the eight paired rows) and the registered sentence
in the line's `detail`, read from `artifacts/staged-context.json`:

> 本行验证阶梯在「爆炸半径确实小于边界」时的花费单调性；本语料 18 个可测行无一为 tier 0（最小 3 个
> importer，边界 `filesMax=3`），故该语料上阶梯不产生节省。观测到的比值属于构造拓扑。

The wording was frozen before the run (preregistration v6). A report whose artefact is missing
prints `upstream_tier0=na` and `counterfactual=not_measured` instead of the sentence; one whose
artefact disagrees with the copy `run.json` froze at staging is refused.

What the line verifies is monotonicity **when the radius really is below the boundary**. That
condition holds for every paired row, so the line is not vacuous — and it is not line 1b's
`na (n=0)` either: there the claim has no sample, here the claim has a sample and a measurement.
What is *not* verified is that the ladder saves tokens on this corpus; on this corpus it cannot,
because no row reaches tier 0 unmodified.

**A sampling property, not a wrong constant.** The 18 staged rows are files that either carry a
defect or sit next to one, so they are cited by construction; `lib/insecurity.ts` with 96
importers is the extreme of that selection. A random sample of changes would put many more rows
below the boundary. `tier 0 is unreachable on this corpus` therefore says nothing about
`tier0.filesMax = 3` — this corpus cannot identify that constant — and moving the constant until
tier 0 appears would be reading a consequence and then adjusting the rule that produced it.

Two further consequences worth naming:

- **The importers are not part of the change.** They are written before the baseline commit,
  carry no code, and never appear in a `ChangeEvent`. What the row measures is unchanged;
  what the tier sees is the repository.
- **The tree the tier is decided on is a subset.** `index build` is ~1.0 s against juice-shop's
  full checkout at 27.9 s, so the projection runs on ~20 files, not 674. `impactedNodes <= 20`
  is easy to satisfy at that size; a real route file can have dozens of dependants and the
  same rule would take another branch. The system decides what it is shown, so the measurement
  is valid, but the conclusion is scoped: **three sources live on a staged subset**, not on a
  full repository.

### The projection is a precondition, not a report

`stageDrill` indexes the staged tree and then asks the real triage layer what each of the 19
rows would decide — `computeTier` over a real `impact` query, no semgrep, no AOR, so the
projection costs no blindness. It mirrors `decideTier` rather than re-deriving the ladder,
because the two baselines do not share one: with `triage.enabled = false` B4g returns tier 2
with source `none` and never queries the graph at all. Each baseline is asserted against what
*its own* config can produce, and staging refuses to start otherwise:

- B4, stratum A (9 negatives): `tier == 0`;
- B4, stratum B (10 positives): `tier >= 1` **by `triage`** — a row that fell back to the
  static ladder is tier 0 and fails the assertion, which is the point: `index_not_ready`
  looks exactly like "the rule says 0";
- B4g: every row `tier == 2` by `none`. A B4g that agrees with B4 means both baselines were
  staged from one config and line 4 would be comparing a run with itself.

At `evaluate` the same rows are checked again, with the price of a flake weighed against the
price of the run. A positive at tier 0 (semgrep ran, AOR did not) keeps its semgrep numbers,
leaves AOR's, is named in `tier0_despite_projection.json` and counted on line 1 as
`aor_excluded`; at three of ten the run is void, because three rows is a broken projection,
not an unlucky one. A negative above tier 0 is still a refusal: line 4's denominator has no
second copy.

### Which side of the ladder B4 and B4g measure

B4g has no ladder, so **AOR runs on all 19 of its rows while B4 runs it on the ten positives
only** — the tier-0 negatives skip it. The pairing on eight low-risk samples therefore
measures *what the ladder excludes*, not what it makes reachable: B4 spends less AOR time and
fewer tokens on the same rows. The two baselines are not "graph vs no graph with equal work";
they differ in which rows reach the second source at all, and that is the effect line 4
attributes.

The contingency table is B4-only by construction (`acceptance.ts` skips other baselines when
it scores findings), so **P2 and P4 are B4 measurements**; B4g contributes line 4's pairing and
nothing else. Writing them up as "B4g could not measure it" would be wrong: B4g ran AOR on
more rows than B4 did.


### A budget below the floor is not a budget

`crgQueryMs` was 300 ms. The graph CLI's own floor is ~600 ms (p99 662 ms over 44 `impact`
calls on the three pinned sources at their pinned commits: goof 662, dvna 639, juice-shop
652; latency is process start, not graph size — 674 files and 10 differ by 8%). So the query
timed out on every live row, `computeTier` never ran, and the tier was the file count. The
blast radius — the third source — had never taken part in a live measurement, including the
fit run.

`crgQueryMs = ceil(p99 x 1.5) = 993 ms`, derived before any tier was computed, frozen in
`artifacts/preregistration.json` as `frozen.budgets.crg_query_ms` with the table above, and
asserted at config load:

```
semgrepKillMs 5000 + crgQueryMs 993 = 5993 <= callMs 8000 = turnMs 8000
```

A relation that is not asserted is two numbers that happen to sit near each other.

993 ms is 1.5× the pooled p99, which is headroom, not a guarantee: on the first upstream pass
one of 19 queries came back at 1133 ms, degraded to `files = 1`, and read as "this file has no
importers" — a false statement about the repository produced by a budget. The measurement now
gives its own queries a 10 s ceiling and records `within_budget` next to the answer, so the
two questions stay separate. In the live run the same event is a tier-0 positive, which the
denominators handle by excluding the row (up to two) rather than voiding the run.

Both pre-path sources are **process-start bound, not work bound**, and that is where half the
call budget goes. Measured here: `impact` costs 0.56 s on a 674-file repository and 0.50 s on
a 10-file one (8%), so the graph query is the CLI's start-up, not the graph. Measured
earlier, not re-measured for this note: semgrep's cold path 2.8 s against 0.65 s warm, the
same shape. Together the two fixed costs are ~3.4 s of the 8 s `callMs`, before either source
has read a line. A budget that treats them as marginal times out the way `crgQueryMs = 300`
did.

### Wiring is checked without degrading a gate

`--allow-degraded` used to double as "let me check the wiring". That is what a bypass for
the measurement gates would have been used for, so wiring now has its own check:

```bash
npm run wiring:check
```

It renders all five lines from **synthesised rows** — no detector runs, no eval sample is
scanned, nothing is read for its content except the defect spans it needs to place a fake
finding — and writes into a temporary directory. Its output says so in the first line, and
a `PASS` there means "the line's inputs are wired", not "the line holds".

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
# 1. stage the one named run directory; the name is the one-shot token
npx tsx scripts/live-drill.ts --stage prepare --allow-eval=eval-ds-2.0.0-<stamp>
# 2..4. the same directory for the rest of the stages
npx tsx scripts/live-drill.ts --stage run     --out runs/live/eval-ds-2.0.0-<stamp>
npx tsx scripts/live-drill.ts --stage collect --out runs/live/eval-ds-2.0.0-<stamp>
npx tsx scripts/live-drill.ts --stage evaluate --out runs/live/eval-ds-2.0.0-<stamp>
```

Stages: `check` → `prepare` → `run` → `collect` → `evaluate` (`--stage <name>` runs one).
`prepare` stages the eval positives the ruleset can gate (10 of 11 on `ds-2`) + **every
defect-free low-risk row** (8 on `ds-2`) + the single `create` behaviour sample + one
dependency-hallucination probe per baseline (`B4`, `B4g`) in `<run>/scratch/<baseline>`,
each its own git repo with the pinned rulesets copied in. `run` drives one headless DSH
session per baseline (write pass, then a correction pass on the same session id), `collect`
maps plugin `ReviewRow`s to the evaluator shape, and `evaluate` writes
`artifacts/acceptance/{report.md,verdict.md,verdict.json}`.

`prepare` refuses to start a second run for the same `dataset_version` unless it is told
why (`--archive-and-restart="<reason>"`), and refuses a plan whose cost estimate exceeds
the frozen ceiling. Both refusals happen before anything is staged or archived.

### The run directory is part of the measurement

Every non-`check` stage refuses a directory whose leaf is not
`eval-<dataset version>-<yyyyMMddTHHmmss>` (or `smoke-...`), and `collect`/`evaluate` refuse
a directory whose `run.json` names another dataset. `run.json` records the dataset version,
the config hash, the frozen pin (including the AOR model), the plan shape, the waived
gates, the one-shot token and any archived restarts, `bundle_check: "mtime"` with both
timestamps, the AOR probe, the cost estimate against its ceiling, and — after `run` — the
actual tokens and wall clock. This is the same rule as instrument identity, applied to the
dataset: a consumer that cannot check identity will eventually mix two measurements. The
ds-1 staging that used to sit in `runs/live` beside the ds-2 run is exactly the entry point
that rule closes.

`plan.controls` stages the defect-free rows the low-risk pool did not take — on `ds-2` that
is the single `create` sample, which is 38 lines and therefore `high` risk. Low-risk rows
that carry a defect are **not** staged (`3` of them on `ds-2`, all fit-split positives):
they would either inflate precision or put a vulnerable file into line 4's pairs. With no
defect-free row at all the evaluator reports `precision: na` and fails line 1 instead of
printing a vacuous `tp/tp = 1.0`.

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
  `OCR_NO_UPDATE=1`. It drifted back to `4236c87` once *after* being pinned — a detached
  `scripts/update.js` from an earlier invocation completed minutes later, which is exactly
  why the gate compares the binary and not the config. Everything else in the preflight
  passes, including `plugin bundle` (`dist/plugin.js` rebuilt after the `instrument`
  change), `aor model` (`deepseek` served `deepseek-flash`, tool-call round trip ok) and
  `frozen pin`.
- **A row names its instruments, down to the model.** `ReviewRow.instrument` carries
  `{semgrep, ocr, aor_model}` next to the declared `toolchain`; `evaluate` **refuses** (not
  warns) when a row's identity is missing, `declared` instead of `observed`, mixed across
  rows, or different from the frozen pin. This is the fourth occurrence of "the artefact
  did not carry its own instrument" (`ts_all` vs `ts_dedup`, `semgrep scan` vs
  `semgrep-core`, `ocr` drift, and now the model behind AOR), so it is a schema field and a
  refusal rather than a checklist item.
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
- **Line 4's pool exists now.** 8 defect-free low-risk rows (all edits); the create sample
  is 38 lines, so it is `high` risk and stays out of the pair pool.
  `low_risk_pool` fails the dataset gate below 8.
- **The create path is exercised once, not measured.** `ts-cwe022-9010` is a `create`
  (`before = ""`, 38 changed lines, content = the vetted text of `ts-cwe601-0001`). It
  proves the create branch is not dead code; `n = 1` and no precision claim is made for it.
  `event_kind` is derived from `before === ""`, and the dataset gate fails if either kind
  disappears from the pool.
- **A one-file write is tier 0 whatever it contains; the positives are lifted by their
  blast radius — which this project wrote.** `staticTier` counts changed *files*
  (`triage.tier0.filesMax = 3`), so the create control `ts-cwe022-9010` — one file, 38 lines,
  `before = ""` — is tier 0, and being a create does not change that. The ten positives are
  staged with three clean importers each (`live/<id>/__importers__/n.ts`, one `import` per
  file), which the graph reports as a four-file blast radius: `tier 1 via triage, files=4,
  nodes=3`. The importers are authored context and every row says so (`authored_context`,
  `authored_importers`); the upstream measurement in `artifacts/staged-context.json` shows the
  same ten files already have 3–96 importers, so **0/10 would be tier 0 unmodified** and the
  tier-1 path is not an artefact of them. Before `crgQueryMs` was repaired the graph could not
  answer at all, so the file count was the whole rule; ADR-0003 勘误二 records that.
- **The tier is computed on ~20 files, not on the repository.** The staged index builds in
  ~1.0 s; juice-shop's full checkout takes 27.9 s. `impactedNodes <= 20` is easy at that size
  and a real route file can have dozens of dependants, so the conclusion is scoped to "three
  sources live on a staged subset". The same is true of line 4's pool: the nine negatives are
  tier 0 because the subset dropped their importers, while upstream 0/9 are tier 0.
- **`triage.enabled = false` means tier 2, not tier 0.** `decideTier` returns
  `{tier: 2, tierSource: "none"}` before it ever looks at the file count
  (`src/l2/orchestrator.ts:119`), so B4g runs AOR on **all** 19 rows and B4 on the ten
  positives only. The B4/B4g pairing therefore measures what the ladder excludes; a write-up
  that calls it "graph vs no graph" gets the direction of the effect wrong.
- **A positive at tier 0 no longer voids the run on sight.** Semgrep ran, AOR did not, so the
  row keeps the block denominators, leaves the correction and anchor ones, is listed in
  `tier0_despite_projection.json`, and line 1 prints `aor_excluded`. Past 2 of 10 the run is
  void: that is a broken projection, not a flake.
- **The three sources have never been live at the same time.** The fit run was a
  two-source measurement: with `crgQueryMs = 300` the graph query could not answer, so the
  tier came from the static ladder and the third source never participated. The repaired
  run is the first in which semgrep, the graph and AOR are all live in the same process —
  and therefore the first whose numbers have no earlier live run to be compared with. This
  is a limitation of the eval, not a footnote.
- **JavaScript is `out_of_scope`.** 6 of the 35 rows are `.js`; the shipped config has no
  JavaScript subset and no `sMax['javascript']`, so they are never scanned. This is the
  second appearance of "declared != shipped" (the first was `ts_all` vs `ts_dedup`): the
  rules table says what exists, the config says what runs, and nothing forces agreement.
  A build-time assertion is the follow-up ticket.
- **Replay recordings are real for fit only.** `tests/fixtures/replay/*` now hold actual
  `semgrep scan` envelopes for the 12 fit rows; the eval recording does not exist yet,
  and `scripts/record-dataset.ts --split eval` refuses to run without `--allow-eval`.
