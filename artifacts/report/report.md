# Code Review Evaluation Report

- config hashes: `0e8a4b7617250dbf01f5c08ad629ac5c1d63e20f1b11c6b766528cb628a774cf`, `52f6fa420c6b7b9c41a259d9731250fc37693d6ebd66a8121bcfc412bcfe2204`, `86c398ffd8fb29f2f9a92810c4bc9ff2aff38f87a283981572a6c6d5b5b6597e`, `9e2a4c8c4c7bd3e3261ef1539cc22bac74fe059a0f455e33b66824eb89e92e7f`, `c713d4124eb63eccb217693bf1851788860530729b9f6d9857af404b4d76f051`
- mode: replay
- rows: 4200

## main 1: detection

| baseline | rows | TP | FP | FN | precision | recall | F1 | unknown_coverage | semgrep_err | aor_err |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B0 | 0 | 0 | 0 | 0 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | n/a | n/a |
| B1 | 840 | 608 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 0.0000 | n/a |
| B2 | 840 | 608 | 840 | 0 | 0.4199 | 1.0000 | 0.5914 | 0.0000 | n/a | 0.0000 |
| B3 | 840 | 608 | 840 | 0 | 0.4199 | 1.0000 | 0.5914 | 0.0000 | 0.0000 | 0.0000 |
| B4g | 840 | 608 | 840 | 0 | 0.4199 | 1.0000 | 0.5914 | 0.0000 | 0.0000 | 0.0000 |
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
| B3 | aor | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B4g | semgrep | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B4g | aor | 840 | 840 | 0 | 0 | 0 | 0.0000 |
| B4 | semgrep | 840 | 840 | 0 | 0 | 0 | 0.0000 |

## main 5: unknown coverage

| baseline | rows | files_covered | files_unknown | unknown_rate |
| --- | --- | --- | --- | --- |
| B0 | 0 | 0 | 0 | 0.0000 |
| B1 | 840 | 840 | 0 | 0.0000 |
| B2 | 840 | 840 | 0 | 0.0000 |
| B3 | 840 | 1680 | 0 | 0.0000 |
| B4g | 840 | 1680 | 0 | 0.0000 |
| B4 | 840 | 840 | 0 | 0.0000 |

## main 6: ablation (B4g)

| ablation (B4g) | rows | precision | recall | F1 | unknown_coverage | semgrep_err | aor_err |
| --- | --- | --- | --- | --- | --- | --- | --- |
| merge=on,conflict=on,calibrate=on,vote=on | 840 | 0.4199 | 1.0000 | 0.5914 | 0.0000 | 0.0000 | 0.0000 |

## main 7: pairing coverage

| baseline | gt spans | matched | unmatched | mean IoU | mean union |
| --- | --- | --- | --- | --- | --- |
| B1 | 210 | 210 | 0 | 1.0000 | 1.4476 |
| B2 | 210 | 210 | 0 | 0.4067 | 3.4476 |
| B3 | 210 | 210 | 0 | 1.0000 | 1.4476 |
| B4g | 210 | 210 | 0 | 0.4067 | 3.4476 |
| B4 | 210 | 210 | 0 | 1.0000 | 1.4476 |

## main 8: counterfactual reclassification

| baseline | rows | counterfactual | rate |
| --- | --- | --- | --- |
| B0 | 0 | 0 | n/a |
| B1 | 0 | 0 | n/a |
| B2 | 0 | 0 | n/a |
| B3 | 0 | 0 | n/a |
| B4g | 0 | 0 | n/a |
| B4 | 0 | 0 | n/a |

## delta: B3 -> B4g

| metric | B3 | B4g | delta |
| --- | --- | --- | --- |
| precision | 0.4199 | 0.4199 | 0.0000 |
| recall | 1.0000 | 1.0000 | 0.0000 |
| f1 | 0.5914 | 0.5914 | 0.0000 |
| tokens (median) | 1200.0000 | 1200.0000 | 0.0000 |

## delta: B4g -> B4

| metric | B4g | B4 | delta |
| --- | --- | --- | --- |
| precision | 0.4199 | 1.0000 | 0.5801 |
| recall | 1.0000 | 1.0000 | 0.0000 |
| f1 | 0.5914 | 1.0000 | 0.4086 |
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
