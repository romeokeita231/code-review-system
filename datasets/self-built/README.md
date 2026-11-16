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

## Population history: `version` did not track the population

Three populations shipped under the **same** manifest `version` (`ds-2.0.0`,
which is also the run-directory prefix `eval-ds-2.0.0-…`). The version therefore
does not identify the population on its own; `content_sha256_root` does:

| commit | samples | pos | neg | `version` | `content_sha256_root` |
| --- | --- | --- | --- | --- | --- |
| `8a62a25` | 33 | 26 | 7 | `ds-2.0.0` | `aee6e0f2caffe243563d158ebfe399681e3e4ac2c89f67cb983c35acc4fca0dd` |
| `5212f9c` | 34 | 26 | 8 | `ds-2.0.0` | `0b1ec9edafd0246a7289b48d1782bf496d27a9cd3d26b0ba472b6daa066a88ad` |
| `e9b63c2` … HEAD | 35 | 26 | 9 | `ds-2.0.0` | `88660232a43cb6d9c8ddc8598fd4a7ff79ec5221afdda886d9254477e9023e8a` |

34 → 35 added one negative (the `create` row `ts-cwe022-9010`); 33 → 34 added
one negative as well. Neither added a positive, so `26/9` versus `26/8` is a
population change, not a measurement change.

`scripts/build-ds2.ts` now refuses to emit a changed root under an unchanged
version, so the next population change fails the build until the version is
bumped. Reading a number off this dataset therefore requires **version + root**,
never the version alone.

## Known limits

The three parents are deliberately vulnerable teaching applications: source and
sink often share one function, there is no sanitisation and no reachability
constraint. Recall measured here is real-defect recall on an easy population,
not a claim about production code. The range sentence, per-class counts and the
`contamination_risk` derivation are in `docs/datasets.md`.
