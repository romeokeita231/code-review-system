/**
 * Wiring check for the acceptance report — **not a measurement**.
 *
 * The old `--allow-degraded` switch existed so a wiring-only drill could run
 * without a green preflight. That turned one switch into a bypass for every gate,
 * including the ones that protect the single eval. This script is the honest
 * replacement: it renders all five lines from **synthesised rows** — no detector
 * runs, no eval sample is scanned, no dataset row is read for its content — and
 * writes into a temporary directory instead of `artifacts/`.
 *
 * What it proves: the plan, the collected-row shape, the truth loader, the unit
 * table, the instrument table, the pair table and the verdict render together.
 * What it does not prove: anything about detection.
 *
 *   npx tsx scripts/wiring-check.ts
 */
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { evaluate, newRunDir, planDrill } from "./live-drill.js";
import { loadFrozenPin } from "./frozen.js";

const DECOY = "SYNTHETIC";

interface SampleFile {
  defects: Array<{ file: string; line_start: number; line_end: number; cwe: string | null }>;
}

function defectsOf(datasetDir: string, sampleId: string): SampleFile["defects"] {
  const raw = JSON.parse(readFileSync(join(datasetDir, "samples", `${sampleId}.json`), "utf8")) as SampleFile;
  return raw.defects;
}

async function main(): Promise<void> {
  const datasetDir = "datasets/self-built";
  const configPath = "configs/b4.json";
  const plan = planDrill(datasetDir);

  // The instrument block is read off the frozen pin, so the check exercises the
  // refusal path with real values; the rows themselves are synthetic.
  const frozen = loadFrozenPin();
  const instrument = {
    semgrep: { name: "semgrep", version: frozen.semgrep.version, commit: null, source: "observed" as const },
    ocr: { name: "ocr", version: "synthetic", commit: frozen.ocr.commit, source: "observed" as const },
    aor_model: {
      provider: frozen.aor_model.provider,
      id: frozen.aor_model.id,
      params: { url: frozen.aor_model.url, configured: frozen.aor_model.configured },
      source: "observed" as const,
    },
  };

  const rows: Array<Record<string, unknown>> = [];
  // After `artifacts/block-gaps.json`'s preregistration time, so the check also
  // exercises the `preregistered` comparison instead of always failing it.
  let ts = Date.parse("2026-11-13T04:00:00Z");
  const push = (entry: Record<string, unknown>): void => {
    ts += 1;
    rows.push({
      mode: "live",
      findings_merged: [],
      sources: [],
      tokens: 1000,
      latency_ms: 1000,
      review_skip_reason: null,
      instrument,
      disposition: { preDecision: "allow", postDecision: "none", finalDisposition: "record", text: null },
      change_event: { sessionId: "wiring", ts, phase: "post" },
      ...entry,
    });
  };

  for (const positive of plan.positives) {
    const defect = defectsOf(datasetDir, positive.sampleId)[0];
    if (defect === undefined) throw new Error(`${positive.sampleId}: no defect span to synthesise from`);
    // One denied write plus one post row carrying a single finding on the span.
    push({
      sample: positive.sampleId,
      baseline: "B4",
      change_event: { sessionId: "wiring", ts, phase: "pre" },
      disposition: {
        preDecision: "deny",
        postDecision: "none",
        finalDisposition: "mechanical_block",
        text: `[${DECOY}] ${defect.file}:${defect.line_start} ${defect.cwe}`,
      },
      findings_merged: [{ file: defect.file, startLine: defect.line_start, endLine: defect.line_end, cwe: defect.cwe }],
    });
    push({
      sample: positive.sampleId,
      baseline: "B4",
      findings_merged: [{ file: defect.file, startLine: defect.line_start, endLine: defect.line_end, cwe: defect.cwe }],
    });
  }

  // One warned sample that is corrected on its next write: lines 3 and 5.
  const warned = plan.positives[0];
  const warnedDefect = warned === undefined ? undefined : defectsOf(datasetDir, warned.sampleId)[0];
  if (warned !== undefined && warnedDefect !== undefined) {
    push({
      sample: warned.sampleId,
      baseline: "B4",
      disposition: {
        preDecision: "allow",
        postDecision: "inject_warn",
        finalDisposition: "instruction_correction",
        text: `[CRS-WARN] ${warnedDefect.file}:${warnedDefect.line_start} ${warnedDefect.cwe} review`,
      },
      findings_merged: [
        { file: warnedDefect.file, startLine: warnedDefect.line_start, endLine: warnedDefect.line_end, cwe: warnedDefect.cwe },
      ],
    });
    push({ sample: warned.sampleId, baseline: "B4" });
  }

  // Line 4: both baselines on every defect-free low-risk row. Each write also
  // gets a pre row, which is where line 1's false-positive denominator is
  // counted from.
  for (const lowRisk of plan.lowRisk) {
    push({ sample: lowRisk.sampleId, baseline: "B4", change_event: { sessionId: "wiring", ts, phase: "pre" } });
  }
  for (const lowRisk of plan.lowRisk) {
    push({ sample: lowRisk.sampleId, baseline: "B4", latency_ms: 1000, tokens: 1000 });
    push({ sample: lowRisk.sampleId, baseline: "B4g", latency_ms: 1200, tokens: 1100 });
  }
  // The defect-free rows outside the low-risk pool: on ds-2 that is the single
  // create sample. Staged like a real row so the precision denominator renders
  // both kinds; it stays out of line 4 because it is not `low` risk.
  for (const control of plan.controls) {
    push({ sample: control.sampleId, baseline: "B4", change_event: { sessionId: "wiring", ts, phase: "pre" } });
    push({ sample: control.sampleId, baseline: "B4", latency_ms: 1000, tokens: 1000 });
    push({ sample: control.sampleId, baseline: "B4g", latency_ms: 1200, tokens: 1100 });
  }

  push({
    sample: plan.probe.sampleId,
    baseline: "B4",
    sources: [
      {
        source: "registry",
        status: "ok",
        findings: [{ file: "package.json", cwe: null, evidence: "package not found: crs-wiring-probe" }],
      },
    ],
  });

  const root = await mkdtemp(join(tmpdir(), "crs-wiring-"));
  const outDir = newRunDir(root, plan.datasetVersion, "eval", new Date("2026-01-01T00:00:00"));
  await mkdir(outDir, { recursive: true });
  await writeFile(
    join(outDir, "run.json"),
    `${JSON.stringify(
      {
        dataset_version: plan.datasetVersion,
        dataset_dir: datasetDir,
        config_hash: "wiring",
        frozen_instruments: frozen,
        created_at: "2026-01-01T00:00:00Z",
        plan: {
          positives: plan.positives.length,
          low_risk: plan.lowRisk.length,
          controls: 0,
          probe: 1,
          negatives_create: [...plan.positives, ...plan.lowRisk, ...plan.controls].filter(
            (sample) => sample.eventKind === "create",
          ).length,
        },
        degraded_gates: [],
      },
      null,
      2,
    )}\n`,
    "utf8",
  );
  await writeFile(
    join(outDir, "rows.jsonl"),
    `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`,
    "utf8",
  );

  const result = await evaluate(outDir, datasetDir, "artifacts/block-gaps.json", join(root, "out"), {
    language: plan.coverage.language,
    perCwe: plan.coverage.declared,
  });

  process.stdout.write(
    "WIRING CHECK - synthetic rows, no detector ran, nothing here is a result.\n" +
      `dataset: ${plan.datasetVersion}  rows: ${rows.length}  pinned: semgrep ${frozen.semgrep.version}, ocr ${frozen.ocr.commit}\n\n` +
      `${result.lines.map((line) => `${line.pass ? "PASS" : "FAIL"} ${line.name} :: ${line.detail}`).join("\n")}\n\n` +
      `rendered ${result.pass}/5 (a PASS here means the line's inputs were wired, not that it holds)\n` +
      `artefacts: ${join(root, "out")}\n` +
      "The real run writes artifacts/acceptance/ and is the only thing that may be quoted.\n",
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
