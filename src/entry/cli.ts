#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { ChangeEvent, type Baseline, type CalibrationArtifact } from "../contracts/index.js";
import { ConfigError, loadCalibration, loadConfig } from "../config/index.js";
import { review } from "../l2/index.js";
import { createSources, createTriage } from "../l3/index.js";
import { appendRow, runReplay } from "../l5/index.js";

async function readEvent(path: string): Promise<ChangeEvent> {
  const parsed = ChangeEvent.safeParse(JSON.parse(await readFile(path, "utf8")));
  if (!parsed.success) throw new ConfigError(`invalid change event ${path}: ${parsed.error.message}`);
  return parsed.data;
}

async function loadArtifact(path: string): Promise<CalibrationArtifact | null> {
  try {
    return await loadCalibration(path);
  } catch {
    return null;
  }
}

async function reviewCommand(values: Record<string, string | undefined>): Promise<void> {
  if (!values.config) throw new ConfigError("--config is required");
  if (!values.event) throw new ConfigError("--event is required");
  const config = await loadConfig(resolve(values.config));
  const event = await readEvent(resolve(values.event));
  const root = resolve(values.root ?? process.cwd());
  const artifact = await loadArtifact(resolve(values.artifact ?? config.calibration.artifactPath));
  if (artifact === null && config.fusionStages.calibrate) {
    throw new ConfigError(`calibration artifact is missing: ${config.calibration.artifactPath}`);
  }
  const outcome = await review(event, {
    runId: values["run-id"] ?? `run-${event.id}`,
    config,
    sources: createSources(config, { root }),
    triage: createTriage(config, { root }),
    artifact,
  });
  const outPath = resolve(values.jsonl ?? config.persistence.jsonlPath);
  await appendRow(outPath, outcome.row);
  process.stdout.write(`${JSON.stringify(outcome.row)}\n`);
}

async function replayCommand(values: Record<string, string | undefined>): Promise<void> {
  if (!values.dataset) throw new ConfigError("--dataset is required");
  const datasetDir = resolve(values.dataset);
  const configured = values.config
    ? await loadConfig(resolve(values.config))
    : await loadConfig(resolve("configs/b4.json"));
  const baselines = (values.baselines ?? "B1,B2,B3,B4g,B4")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
  const artifact = await loadArtifact(resolve(values.artifact ?? configured.calibration.artifactPath));
  if (artifact === null && configured.fusionStages.calibrate) {
    throw new ConfigError(`calibration artifact is missing: ${configured.calibration.artifactPath}`);
  }
  await runReplay({
    datasetDir,
    config: configured,
    artifact,
    repoRev: values["repo-rev"] ?? "datasets/self-built",
    baselines: baselines as Baseline[],
    outDir: resolve(values.out ?? "runs"),
    runIdPrefix: values["run-id"] ?? "replay",
    recordedDir: values.recorded ? resolve(values.recorded) : resolve("tests/fixtures/replay"),
  });
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);
  const { values } = parseArgs({
    args: rest,
    options: {
      config: { type: "string" },
      event: { type: "string" },
      artifact: { type: "string" },
      jsonl: { type: "string" },
      root: { type: "string" },
      dataset: { type: "string" },
      out: { type: "string" },
      baselines: { type: "string" },
      recorded: { type: "string" },
      "repo-rev": { type: "string" },
      "run-id": { type: "string" },
    },
  });
  if (command === "review") {
    await reviewCommand(values);
    return;
  }
  if (command === "replay") {
    await replayCommand(values);
    return;
  }
  throw new ConfigError("usage: crs <review|replay> [options]");
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`${message}\n`);
  process.exitCode = 1;
});
