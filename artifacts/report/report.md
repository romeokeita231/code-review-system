# Code Review Evaluation Report

- config hashes: `1382da17a502eeb53bb096d8617b36a5b707750881a706a1eebf2440870bd767`, `31ec24355ba312ab679417b6bd0a677530bfb6f26ec1b4aea4b1d33f8dfd2384`, `7e92ed44ac2f5fac4a584353b0206a794f81f25b3d52af734e5af99895446399`, `c78c82aae6ba4ee0ecd41660a49f2e020a5b449aa32fa0d433b00c624077370d`, `ea870314dbb8c8807ee63d91f04069e4642bfdd72ac83cb490143ccc93e7c82c`
- mode: replay
- rows: 4200

## main 1: detection

| baseline | rows | TP | FP | FN | precision | recall | F1 | unknown_coverage | semgrep_err | aor_err |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | 0 | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | n/a | n/a |
| B1 | 840 | 608 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |
| B2 | 840 | 608 | 840 | 0 | 0.4199 | 1.0000 | 0.5914 | 0.0000 | n/a | 0.0000 |
| B3 | 840 | 608 | 832 | 0 | 0.4222 | 1.0000 | 0.5938 | 0.0000 | 0.0000 | 0.0000 |
| B4g | 840 | 608 | 832 | 0 | 0.4222 | 1.0000 | 0.5938 | 0.0000 | 0.0000 | 0.0000 |
| B4 | 840 | 608 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |

## main 2: block

| baseline | n | k | TP | FP | FN | block precision | block recall | n>=15 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | 0 | 0 | 0 | 0 | 0 | 0.0000 | 0.0000 | no |
| B1 | 840 | 420 | 420 | 0 | 0 | 1.0000 | 1.0000 | yes |
| B2 | 840 | 0 | 0 | 0 | 420 | 0.0000 | 0.0000 | yes |
| B3 | 840 | 420 | 420 | 0 | 0 | 1.0000 | 1.0000 | yes |
| B4g | 840 | 420 | 420 | 0 | 0 | 1.0000 | 1.0000 | yes |
| B4 | 840 | 420 | 420 | 0 | 0 | 1.0000 | 1.0000 | yes |

## main 3: cost

| baseline | rows | files_scanned (median) | tokens (median) | latency_ms (median) |
| --- | --- | --- | --- | --- |
| B0 | 0 | n/a | n/a | n/a |
| B1 | 840 | 420.0000 | n/a | 0.0000 |
| B2 | 840 | 420.0000 | 1200.0000 | 0.0000 |
| B3 | 840 | 420.0000 | 1200.0000 | 0.0000 |
| B4g | 840 | 420.0000 | 1200.0000 | 0.0000 |
| B4 | 840 | 420.0000 | n/a | 0.0000 |

## main 4: per-source errors

| baseline | source | total | ok | timeout | error | degraded | error_rate |
| --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | semgrep | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B2 | aor | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B3 | semgrep | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B3 | aor | 834 | 834 | 0 | 0 | 0 | 0.0000 |
| B4g | semgrep | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B4g | aor | 836 | 836 | 0 | 0 | 0 | 0.0000 |
| B4 | semgrep | 840 | 840 | 0 | 0 | 0 | 0.0000 |

## main 5: unknown coverage

| baseline | rows | files_covered | files_unknown | unknown_rate |
| --- | --- | --- | --- | --- |
| B0 | 0 | 0 | 0 | 0.0000 |
| B1 | 840 | 840 | 0 | 0.0000 |
| B2 | 840 | 840 | 0 | 0.0000 |
| B3 | 840 | 1674 | 0 | 0.0000 |
| B4g | 840 | 1676 | 0 | 0.0000 |
| B4 | 840 | 840 | 0 | 0.0000 |

## main 6: ablation (B4g)

| ablation (B4g) | rows | precision | recall | F1 | unknown_coverage | semgrep_err | aor_err |
| --- | --- | --- | --- | --- | --- | --- | --- |
| merge=on,conflict=on,calibrate=on,vote=on | 840 | 0.4222 | 1.0000 | 0.5938 | 0.0000 | 0.0000 | 0.0000 |

## delta: B3 -> B4g

| metric | B3 | B4g | delta |
| --- | --- | --- | --- |
| precision | 0.4222 | 0.4222 | 0.0000 |
| recall | 1.0000 | 1.0000 | 0.0000 |
| f1 | 0.5938 | 0.5938 | 0.0000 |
| tokens (median) | 1200.0000 | 1200.0000 | 0.0000 |

## delta: B4g -> B4

| metric | B4g | B4 | delta |
| --- | --- | --- | --- |
| precision | 0.4222 | 1.0000 | 0.5778 |
| recall | 1.0000 | 1.0000 | 0.0000 |
| f1 | 0.5938 | 1.0000 | 0.4062 |
| tokens (median) | 1200.0000 | n/a | n/a |

## appendix A: cache

| baseline | cache | rows | tokens (median) | variance |
| --- | --- | --- | --- | --- |
| B0 | cold | 0 | n/a | n/a |
| B0 | warm | 0 | n/a | n/a |
| B1 | cold | 840 | n/a | n/a |
| B1 | warm | 0 | n/a | n/a |
| B2 | cold | 840 | 1200.0000 | 0.0000 |
| B2 | warm | 0 | n/a | n/a |
| B3 | cold | 840 | 1200.0000 | 0.0000 |
| B3 | warm | 0 | n/a | n/a |
| B4g | cold | 840 | 1200.0000 | 0.0000 |
| B4g | warm | 0 | n/a | n/a |
| B4 | cold | 840 | n/a | n/a |
| B4 | warm | 0 | n/a | n/a |

## appendix B: cost extrapolation

| model | a | b | R^2 | points | extrapolation sizes | observed |
| --- | --- | --- | --- | --- | --- | --- |
| f(files_reviewed) = a*x + b | n/a | n/a | n/a | 1 | 30, 100, 250 | 420:1200 |
