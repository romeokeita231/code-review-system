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

Two of the three parents named by §4 contain **no TypeScript at all**, while §13
fixes `language: "ts"`. The parent list therefore cannot yield ready-made rows:
Juice Shop is the only parent that is already TypeScript (an Angular front end plus
an Express server).

Three ways to build the set, in descending order of fit:

1. **Port a child of `nodejs-goof` / `dvna` into TypeScript inside a project whose
   `tsc --noEmit` passes.** The schema already has `origin.kind = self_rewritten`
   for exactly this, and §4.4 requires structural rewriting anyway. This keeps the
   Express context (imports, routes, DAOs) that the current hand-written samples
   lack, and is the only route that covers all seven classes.
2. Use Juice Shop alone for the classes it actually contains (injection, XSS, broken
   access control) and accept a smaller set.
3. Relax §13 to `language: "js"`, which would invalidate the TypeScript ruleset
   coverage numbers the drill depends on.

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
