# Evaluation sets

Four sets are named in the annotation spec (#7 §3). Only two exist on disk; the
status of each is recorded here so a number can always be traced to a set that
actually passed a gate.

| Set | Path | Role | Status |
| --- | --- | --- | --- |
| self-built (`ds-2`) | `datasets/self-built` | fit + eval, per-CWE P/R | 33 rows (26 pos / 7 neg), 28 groups; gate + conformance PASS |
| AACR-Bench TS | `datasets/aacr` | eval only: Precision / noise rate | imported 2026-11-12, conformance PASS |
| SecurityEval | — | fit only (class priors) | not imported |
| CWE-Bench-Java | — | external sanity only | not imported |

## #7 errata: D1 (negatives) and D2 (calibration)

Two rules the spec stated loosely enough that the old set satisfied them by
accident. Both are now machine-checked.

**D1 — a sample has to be a real change, and a safe variant has to name the
control.** `--conformance` gained four hard failures:

| rule | what it rejects |
| --- | --- |
| `noop` | `sha256(before) === sha256(after)`, or a diff that touches only comments/blank lines |
| `rationale` | a `variant_of` row with no `rationale`, or one that is not a control name (`已修改`, `modified`, `safe version`, … are rejected; the named control is still the annotator's call) |
| `variant` | a variant whose `file_path` or `sample_cwe` differs from the row it is a variant of |
| `version` | a `self` row that is not `schema_version: 2`, or a manifest that is not `ds-2` |

All 210 old pair-safe variants trip `noop` (they are `before === after`), which is
the point: they were a precision denominator that was true by construction. The
rebuilt set is `schema_version: 2` / `ds-2`; external imports (AACR) stay at 1.

**D2 — calibration categories are derived, not listed.** `CALIBRATION_CATEGORIES`
(hand-written `[…, CWE-502, …]`, CWE-918 missing) is gone. The set is

```
categories = (dataset manifest 的 sample_cwe 集合) ∩ (规则表声明的 CWE 集合)
```

computed by `calibrationCategories()` over the languages the config actually
scans. `artifacts/calibration.json` now carries `dataset_version`,
`ruleset_fingerprint` (sha256 of `rules_table.json`) and `categories`;
`assertCalibrationMatches()` is a **hard failure** on any mismatch, and the drill's
`check` stage runs it before a live run. Re-running `npm run calibrate` on the
current drifted set shows the effect: 75 `CWE-502` findings are dropped from the
fit and reported as `categories_dropped`, because the ruleset never declared 502 —
their grids would otherwise have survived the 502→918 change and applied a
threshold nobody fitted.

**Degraded calibration rule (spec-level).** With 7 classes × 30 declarations the
per-class threshold is unreachable by construction: every `category.*` entry is
`skipped: class_declarations_below_30` and only the global `block`/`warn` pair is
fitted. That is not a bug to be worked around. When a class has fewer than 30
declarations, report its descriptive numbers (n, interval) and **no threshold**;
the pipeline uses the global threshold for every class. A per-class threshold may
only appear once that class passes 30.

## self-built (`ds-2`)

The set is generated, never hand-edited: `scripts/build-ds2.ts` reads
`source/rows.json` (mechanical row description + line hunks) and
`source/provenance.json` (pinned commits, star snapshot, supply records), then derives
`before`/`after`, `changed_lines`, `risk_level`, `defect_id`, `defect_origin`,
`contamination_risk`, the split, the hashes and the manifest projection.

```bash
npm run dataset:build     # --emit: rewrite the tree from the pinned blobs
npm run dataset:check     # emit in memory, compare byte for byte, then run the gate
npm run dataset:verify    # the gate: offline, no network, no detector
```

`--check` is the reproducibility claim: it re-reads every upstream blob at its pinned
commit, asserts the pinned `blob_sha`, rebuilds `before` from `after` plus the recorded
hunks, and compares all 34 files with the committed tree. `datasets/self-built/**` is
marked `-text` in `.gitattributes`, because on a machine with `core.autocrlf=true` a
checkout would otherwise rewrite the tree to CRLF and turn the byte comparison red — a
reproducibility claim that does not survive another machine is not one.

`verifyDataset` and `--conformance` answer different questions ("the files agree with
the manifest" vs "the rows agree with the spec"). Both pass on `ds-2`; the old set
failed the second with ~3300 violations, which is why replay recall looked clean while
live line 1 measured 0.

### What a row is, exactly

| field | value | why |
| --- | --- | --- |
| `after` | the upstream blob, byte for byte (`origin.blob_sha`) | the detector sees real code |
| `before` | our minimal pre-image: `after` plus one re-added control | only builds the change event and `changed_lines`; **no detector sees it** |
| `defect_origin` | `real` on positives, `null` on negatives | the vulnerable bytes are the upstream author's; the project authored the pre-image only |
| `origin.kind` | `public_repo` | `after` is upstream; `self_rewritten` would misdescribe it |
| `contamination_risk` | derived from §10, not filled in | see below |

**Range sentence.** Self-built recall is *real-defect* recall over 26 upstream vulnerable
files. The limit is the **parent population**: all three sources are deliberately
vulnerable teaching applications, with source and sink often in one function, no
sanitisation and no reachability constraint, so they are easier to detect than production
code. This is not evidence that generalises to production code.

**`contamination_risk` (revised §10).** `high` iff `origin.kind = public_repo` and either
`origin.advisory` is set or the source is `pedagogical` with `stars >= 1000`; else `low`.
Star counts are a dated snapshot (`declared.contamination_stars_as_of`). With the
2026-11-12 snapshot the rule *splits* the set: juice-shop (14,433) gives 27 `high`, while
goof (549) and dvna (781) stay `low`. The teaching-app flag alone does not establish that
a file is in a training corpus.

**Negatives, held out on purpose.** 7 rows, all from juice-shop, all in eval
(`declared.negatives_split: "eval"`): the threshold must never be fitted against the rows
that measure precision. A file that already hosts a positive cannot host a negative — the
positive's `before` is that file plus a control, so the pair is a near-duplicate and the
split would leak the label. The builder throws on it and the gate re-checks it.

**Supply exhaustion, not "insufficient_n".** CWE-078 (2 rows) and CWE-918 (1 row) are
below the reporting threshold. Each carries a `declared.supply_exhausted` record that
names every source searched and the verdict for each (`no sink` / `1 real sink` + the
line). The gate refuses an `insufficient_n` class without one, so "we looked and the
source is dry" can never be written as "too few samples".

### Calibration cannot be fitted on `fit_negatives = 0`

Holding the negatives out for a single, blind precision measurement has a price: the fit
split has no negative, so every finding is a true positive, PAVA collapses every score
towards 1.0, and no operating point can be certified. `artifacts/calibration.json`
records the outcome as `thresholds.status: "unfittable"` with all three causes:

| cause | value | nature |
| --- | --- | --- |
| `fit_negatives` | 0 | **design choice** — precision is measured once, in eval |
| `class_declarations` | 4 (max, one class) | corpus size (the per-class gate wants ≥30) |
| `n_fit` | 4 findings | corpus size |

`class_rules` (11) sits next to them as context: it is what the pinned ruleset declares
for the class that did produce findings (CWE-089 in TypeScript). This is a recorded
trade-off, not a bug: fitting a threshold later requires putting some negatives into
fit, and then precision has two numbers — a fitted-side estimate and an acceptance-side
measurement — which must never be quoted interchangeably.

### Two limitations that belong in the paper

1. **No defect-free low-risk row.** 11 of the 33 rows are `risk_level: low` (079/798 with
   changes ≤30 lines), so the tier ladder does see both levels — but every low row is a
   *positive*, and line 4 needs 8 **defect-free** low-risk samples to pair B4 against B4g.
   On `ds-2` those pairs would be built on defective rows, which is why line 4 is
   unmeasurable here rather than merely thin.
2. **Language coverage is part of the claim.** The shipped config scans Python and
   TypeScript; `ds-2` is 27 TypeScript + 6 JavaScript rows. The 6 JavaScript rows are
   `out_of_scope` (never attempted), not misses — see `docs/live-drill.md`. Line 1's
   `n >= 20` is also out of reach: the eval split has 14 positives (11 TypeScript), so the
   live drill stages 10 and fails the size gate on the data, not on detection.

## P2 supply check (measured 2026-11-12)

`gh api repos/<repo>/git/trees/<sha>?recursive=1` at each parent's HEAD:

| Parent | files | `.ts`/`.tsx` | `.js`/`.jsx` |
| --- | --- | --- | --- |
| `snyk-labs/nodejs-goof` | 60 | **0** | 10 |
| `appsecco/dvna` | 151 | **0** | 14 |
| `juice-shop/juice-shop` | 1498 | 664 | 9 |

`language` is `ts | js` (#41 裁定), so the two JavaScript-only parents are admissible;
the binding question was how many real defects they contain, not which language.

### 第 1 步：候选清点 (2026-11-12)

Full table, evidence and per-row judgement: `research/dataset-candidates/inventory.md`
(+ `inventory.json`). Method: `git grep` for each class, then read every hit to check
the data flow and the control. No detector was run; no label was written.

| class | real candidate sites | where |
| --- | --- | --- |
| 022 | 5 | `dataErasure`, `fileServer`, `vulnCodeSnippet`, `vulnCodeFixes`, `fileUpload` |
| 078 | 1 | goof `routes/index.js:174` (`exec('identify ' + url)`) |
| 079 | 7 | `search-result` ×2, `data-export`, `track-result`, `administration` ×2, `last-login-ip` |
| 089 | 2 | `routes/search.ts:23`, `routes/login.ts:34` |
| 094 | 4 | `userProfile` (`eval`), `b2bOrder` / `fileUpload` / `lib/xml.ts` (vm) |
| 798 | 4 | juice-shop RSA private key literal; goof token / session secret / seed password |
| 918 | 1 | `routes/profileImageUrlUpload.ts:24` (`fetch(req.body.imageUrl)`) |

- **All seven classes have a real source; no class reaches five.** 022 (5) and 079 (7)
  do; 094 and 798 sit at 4; 089 at 2; 078 and 918 at 1. Total 24 sites, so line 1's
  `n ≥ 20` is reachable while "≥5 classes × ≥5 positives" is not.
- Juice Shop has **zero** 078 sinks (its only `child_process` hit is a Cypress fixture
  and every `exec` hit is `RegExp.exec`); 078 comes from goof and from nowhere else.
- Three sites are `fp_bait` — the same dangerous call already guarded upstream
  (`logfileServer`, `quarantineServer`, `keyServer` all reject `/` in the param). Real
  code, real sink, real control: a better precision denominator than an authored
  "safe variant". Five more are `sink_only` and must never become positives (e.g.
  `routes/captcha.ts:22` evals an expression built only from `Math.random`).
- The 169 files under `data/static/codefixes/` are **fragments** — no imports,
  `botName` / `productModel` / `req` undefined — so they cannot be samples and would
  fail `tsc --noEmit`. That is the same defect E2 named, in canned form.

**Diff provenance is the binding constraint, not class count.**

```
git log -S'models.sequelize.query' -- routes/search.ts     # 23,854-commit history
→ d6dc878b1 2021-03-05 "Migrate /routes/*.js to .ts"
```

The TypeScript form of the sink arrived in a bulk migration commit, not in a
vulnerability-introducing one (a single `-S` probe over the lazy blob filter costs
~105 s through the proxy). A real `before`/`after` therefore only exists either as a
2016-era ES5 introduction (the file was `.js`, or did not exist yet) or as one of these
migration commits. Self-built positives can only be **real file + authored minimal
diff**, with `origin.kind = self_rewritten` and `contamination_risk = authored-diff`
recorded. That is not "hand-written samples" (§4 forbids inventing code) but it must be
stated, or the rows will be read as upstream commits.

Two readings of the step-2 rule disagree and the choice is a spec decision:

- **Strict (≥5 classes × ≥5 rows):** no class qualifies → the self-built set is not an
  evaluation set; keep it as a measured coverage report on real repos and let line 1
  rest on AACR (22 rows, conformance PASS).
- **By totals (n ≥ 20 with all seven classes present):** 23 rows satisfy `n ≥ 20`; the
  three thin classes (089 `n=2`, 078 `n=1`, 918 `n=1`) report `n` and an interval only,
  never a threshold.

Neither reading changes line 1's block facet, which is `na` regardless (#41 第 0 步:
no certified TS block rule).

Annotation stays human (§5: 主标本人, advisor spot-check at κ ≥ 0.70). The
machine-checkable part — provenance, `origin`/`contamination_risk`, the `tsc` gate,
the 3:2 split, the §9 risk derivation — is what `--conformance` enforces once the
rows exist.

## AACR-Bench (imported)

Source: [`alibaba/aacr-bench`](https://github.com/alibaba/aacr-bench), Apache-2.0,
dataset `v1` (`dataset/v1/positive_samples.json`, `dataset/v1/negative_samples.json`).

```bash
# fetch the two JSON files into .tmp/aacr (gh api is the only network path here)
npx tsx scripts/import-aacr.ts --raw .tmp/aacr --out datasets/aacr
npx tsx scripts/verify-dataset.ts --conformance datasets/aacr   # must PASS
```

Mapping, all of it from #7 §11:

- `side=LEFT` is dropped: a deleted line has no anchor in the new file.
- `sample_cwe` and `defects[].cwe` are `null`. AACR has no CWE, so these rows must
  never enter a per-CWE table.
- `from_line`/`to_line` are **comment positions**, not defect ranges. They are stored
  verbatim and the `evidence` string says so; AACR's own metric scores by range
  overlap, so a >3-line span is faithful here and only the self-built set is held to
  the §13 tight-span rule.
- `before`/`after` are the file at the PR's `source_commit`/`target_commit`, fetched
  through `gh api` (contents, with a git-blob fallback above the inline limit).
- `label`: 1 for comments the dataset marks as real security issues, 0 for the
  negative collection.

Accounting (§11 forbids reporting only survivors) — `import-report.json`:

| | value |
| --- | --- |
| raw comments in `v1` positives | 1506 |
| TS `Security` positives / negatives | 7 / 8 |
| LEFT dropped in this stratum | 0 (the 11 LEFT rows in `v1` are all outside it) |
| dropped for not being TypeScript | 5 (e.g. a `Makefile`, `*.json`) |
| imported | 22 = 7 positive + 8 security-negative + 7 non-Security control |
| ratio before → after | 7:8 → 7:15 |

**n = 7 is the whole TS/JS `Security` population of `v1`**, not a subsample. It is
enough to exercise the pipeline and to report a noise rate with a very wide interval;
it is not enough to support a precision claim on its own. `dataset/v2` exists with 151
PRs and no LEFT rows — a possible extension, deliberately not mixed in.

The importer is re-runnable and deterministic: the control arm is picked by
`sha256(pr|path|line|note)` order, and fetched file contents are cached under
`.tmp/aacr/cache`.
