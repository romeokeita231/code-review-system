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
| semgrep 1.184.0, code-review-graph 2.3.9, ocr | same check |
| Dataset is semgrep-detectable | same check scans planned positives with `ts_all.yaml` |

Run the gate first — it exists so a run fails for the right reason:

```bash
npx tsx scripts/live-drill.ts --stage check
```

## Run

```bash
npx tsx scripts/live-drill.ts --stage all
```

Stages: `check` → `prepare` → `run` → `collect` → `evaluate` (`--stage <name>` runs one).
`prepare` stages 20 eval positives + 8 low-risk samples + one dependency-hallucination
probe per baseline (`B4`, `B4g`) in `runs/live/scratch/<baseline>`, each its own git
repo with the pinned rulesets copied in. `run` drives one headless DSH session per
baseline (write pass, then a correction pass on the same session id), `collect` maps
plugin `ReviewRow`s to the evaluator shape, and `evaluate` writes
`artifacts/acceptance/{report.md,verdict.md,verdict.json}`.

`--allow-degraded` skips the gate for a wiring-only run; it cannot produce a passing
verdict.

## Two Windows-only traps

1. **Never launch `dsh` through the `dsh.ps1` shim from a sandboxed shell.** That
   process tree cannot open the certificate store, and `semgrep-core` dies in its CA
   bootstrap (`CertOpenSystemStore returned NULL`) before matching any rule. The drill
   invokes `node .../@deepseek-ai/dsh/lib/bin.js` directly for this reason.
2. **Ruleset paths in `configs/*.json` are repo-relative.** The adapter resolves them
   against its root, so a scratch repo needs the same tree; `prepare` copies the
   snapshots. Without it every scan reports `rules_missing`.

## Known blockers (2026-11-12)

- The self-built dataset is **not semgrep-detectable**: 0/20 planned positives match
  `research/semgrep-bench/snapshot/ts_all.yaml`. `expected_detectable_by: ["semgrep"]`
  in the manifest is therefore unbacked, and line 1 cannot reach recall ≥ 0.70.
- The replay fixtures under `tests/fixtures/replay/*/semgrep.json` are synthetic
  (`evidence: "recorded semgrep hit #1"`), so replay recall/precision are placeholders,
  not measurements.
- `ocr` self-updates past the pinned `04deca6` (observed v1.13.8); re-pin before
  quoting AOR numbers.
