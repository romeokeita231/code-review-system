# Evaluation sets

Four sets are named in the annotation spec (#7 §3). Only two exist on disk; the
status of each is recorded here so a number can always be traced to a set that
actually passed a gate.

| Set | Path | Role | Status |
| --- | --- | --- | --- |
| self-built TS | `datasets/self-built` | fit + eval, per-CWE P/R | **not spec-conformant, blocking line 1** |
| AACR-Bench TS | `datasets/aacr` | eval only: Precision / noise rate | imported 2026-11-12, conformance PASS |
| SecurityEval | — | fit only (class priors) | not imported |
| CWE-Bench-Java | — | external sanity only | not imported |

## self-built

`npx tsx scripts/verify-dataset.ts` checks the set against its own manifest
(hashes, counts, pairing, split leakage). It passes.

`npx tsx scripts/verify-dataset.ts --conformance` checks it against the spec and
fails with ~2600 violations across 5 rules: field names (`cwe`/`path`/`paired_safe`
instead of `sample_cwe`/`file_path`/`variant_of`), `sample_id` pattern, `medium` risk
levels that §9 cannot derive, CWE-502 where §6 asks for CWE-918, and 60 rows per class
instead of a 3:2 fit/eval split.

Both checks exist because they answer different questions. The first says "the files
agree with the manifest"; the second says "the dataset agrees with the spec". A dataset
whose schema drifted passes the first perfectly — which is exactly what happened, and
why replay recall/precision looked clean while live line 1 measured 0.

Two further defects, found while measuring:

- All 210 pair-safe "variants" are no-op writes (`before === after`,
  `changed_lines = 0`). They are "no change", not "changed but safe", so they cannot
  serve as a precision denominator.
- The manifest's `expected_detectable_by` is uniformly `["semgrep", "aor"]`, i.e. it
  carries no information. It must not select the recall denominator (#7 §6) — the
  ruleset's *declared* coverage does that now (see `docs/live-drill.md`).

Rebuilding this set is P2 of the #41 sequence: parents from `nodejs-goof` / `dvna` /
Juice Shop with a `tsc --noEmit` gate, CWE-502 replaced by CWE-918, `origin` /
`repo` / `contamination_risk` filled in, `risk_level` re-derived.

### P2 supply check (measured 2026-11-12)

`gh api repos/<repo>/git/trees/<sha>?recursive=1` at each parent's HEAD:

| Parent | files | `.ts`/`.tsx` | `.js`/`.jsx` |
| --- | --- | --- | --- |
| `snyk-labs/nodejs-goof` | 60 | **0** | 10 |
| `appsecco/dvna` | 151 | **0** | 14 |
| `juice-shop/juice-shop` | 1498 | 664 | 9 |

`language` is now `ts | js` (#41 裁定), so the two JavaScript-only parents are
admissible after all; the question is no longer which language can be used but how
many real defects the parents actually contain.

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
