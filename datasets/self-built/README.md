# `datasets/self-built` - the name means a self-built **selection**

The directory name reads like "self-written code". It is not. All 35 samples'
`after` fields are byte-identical copies of files from three public
repositories, each pinned by commit. What this project authored is the
**selection**, the labels, and the pre-image (`before`) that turns a file into a
change event.

The per-sample `origin` block is the authority, not this file:

| fact | value | how it is known |
| --- | --- | --- |
| `origin.kind` | `public_repo` on **35/35** samples (0 `self_rewritten`, 0 synthetic) | read from the samples |
| `origin.ref` | **29** `juice-shop/juice-shop@266448a…`, **4** `snyk-labs/nodejs-goof@add14ba…`, **2** `appsecco/dvna@9ba473a…` | read from the samples |
| `origin.blob_sha` | pins the base blob; on a positive, `after` equals that blob byte for byte | `npm run dataset:check` re-reads every blob and compares all 35 files |
| `contamination_risk` | `high` on **35/35** | derived from §10 (`docs/datasets.md`), not filled in |

What is authored: a positive's `before` re-adds one control so that a change
event exists (no detector ever sees it, and the vulnerable bytes are the
upstream author's - `defect_origin: "real"`); a negative's `after` adds one safe
edit to the pinned blob. `source/rows.json` describes the rows mechanically,
`source/provenance.json` carries the pinned commits, and `scripts/build-ds2.ts`
derives everything else, including the manifest.

## Why the directory is not renamed

Renaming it would change every sample's `path`, every `content_sha256` in
`manifest.json`, and the sample ids the archived run
`runs/live/eval-ds-2.0.0-20261114T132232` cites - `artifacts/acceptance/rows.jsonl`'s
171 rows are keyed by 20 sample ids, 19 of them from this directory (the
twentieth is the dependency probe). A more accurate name is not worth
invalidating the archived evidence, so this file is the correction instead.

## Known limits

The three parents are deliberately vulnerable teaching applications: source and
sink often share one function, there is no sanitisation and no reachability
constraint. Recall measured here is real-defect recall on an easy population,
not a claim about production code. The range sentence, per-class counts and the
`contamination_risk` derivation are in `docs/datasets.md`.
