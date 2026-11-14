# 验收结果表（live）

instruments (observed in the reported process, equal to the pin):

| tool | version | commit | source |
| semgrep | 1.184.0 | - | observed |
| ocr | v1.13.6 | 04deca6 | observed |

| aor model | served id | requested | endpoint | source |
| deepseek | deepseek-flash | deepseek-chat | https://api.deepseek.com | observed |

The model is the deepest instrument: `ocr`'s commit says which client asked, the served id says which model answered. Both are compared with the frozen pin.

| line | state | detail |
| line1: block precision/recall on the covered, scannable eval positives | NA | mode=live recall n=10 samples (50 pre rows) (available=11 staged=10) hits=0 recall=0.000 wilson=[0.000,0.278] recall_gate=na certified=0/10 block_face=na (no certified TS rule (blockRules is empty for this language in the pinned config)) precision findings=86 tp=13 precision=0.151 without_class=81 precision_gate=gated negatives=11 (edit=10 create=1) excluded=0 out_of_scope=0 aor_excluded=0 preregistered_gaps=true predicted_gaps=0 |
| line2: dependency hallucination closed by a registry hit | PASS | mode=live registry_hits=2 |
| line3: no repeat of the same class after a correction | FAIL | warned_rows=53 warned_samples=20 classed=10 samples corrected=0 recurred=1(ts-cwe798-0001) unfixed=9(ts-cwe079-0004,ts-cwe022-0001,ts-cwe918-0001,ts-cwe094-0002,ts-cwe079-0003,ts-cwe022-0002,ts-cwe094-0004,ts-cwe079-0007,ts-cwe079-0005) | rows corrected=26 recurred=4 unfixed=10 | criterion=all-warns-handled (precedence recurred>unfixed>corrected) |
| line4: B4 vs B4g paired token/latency ratios on 8 low-risk samples | PASS | source=live pairs=8 undetermined=0 median_token_ratio=na (raw: measured on both sides for 0/8 pairs) median_token_ratio_derived=0.000 (derived: 8/8 pairs had AOR not invoked [aor_invoked:false 0, tier 0 via triage 8] -> AOR calls 0; B4g tokens 9438-39037) median_latency_ratio=0.041 available_pairs=8 upstream_tier0=0/8 counterfactual=本行验证阶梯在「爆炸半径确实小于边界」时的花费单调性；本语料 18 个可测行无一为 tier 0（最小 3 个 importer，边界 `filesMax=3`），故该语料上阶梯不产生节省。观测到的比值属于构造拓扑。 |
| line5: correction anchor visible on the next request | PASS | warned=53 anchored=53 |

line1 units (the two faces do not share a denominator):

| face | unit | n | gate | status |
| recall | sample | 10 samples (50 pre rows) | >= 20 | na (no certified TS rule (blockRules is empty for this language in the pinned config)) |
| precision | finding | 86 | >= 20 | gated |

line1 false-positive denominator: 11 defect-free rows (10 edit, 1 create); the create path is a smoke sample (n=1) and no precision claim is made for it

shortfall: 11 eval positives are gateable, 10 were staged

| sample | event | B4/B4g token ratio | B4/B4g latency ratio |
| ts-cwe022-9001 | edit | 0.000 * | 0.071 |
| ts-cwe022-9002 | edit | 0.000 * | 0.049 |
| ts-cwe022-9003 | edit | 0.000 * | 0.064 |
| ts-cwe022-9008 | edit | 0.000 * | 0.033 |
| ts-cwe079-9005 | edit | 0.000 * | 0.046 |
| ts-cwe094-9004 | edit | 0.000 * | 0.029 |
| ts-cwe601-0001 | edit | 0.000 * | 0.036 |
| ts-cwe918-9007 | edit | 0.000 * | 0.028 |

* derived: AOR was never asked on the B4 row (aor_invoked:false 0, tier 0 via triage 8), so its AOR cost is 0 by construction rather than unmeasured; the B4g row measured 9438-39037 tokens. The raw ratio for those pairs is `na`, and both numbers are printed above.

line1 denominator by class (declared typescript rules):

| class | declared rules | eval rows | outside line1 |
| CWE-022 | 3 | 12 | no |
| CWE-079 | 35 | 21 | no |
| CWE-094 | 13 | 6 | no |
| CWE-798 | 6 | 7 | no |
| CWE-918 | 19 | 4 | no |
