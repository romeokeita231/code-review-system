import { mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  effectiveConfigHash,
  loadDataset,
  loadRecorded,
  readJsonl,
  runBaseline,
  runReplay,
  unknownCoverage,
  sourceErrorRates,
  type DatasetSample,
  type PairingRow,
  type RunRecord,
} from "../../src/l5/index.js";
import { finding, makeConfig, makeSample, result, writeDataset, writeRecorded } from "./helpers.js";

interface Fixture {
  root: string;
  datasetDir: string;
  recordedDir: string;
  samples: DatasetSample[];
}

async function prepare(): Promise<Fixture> {
  const root = await mkdtemp(join(tmpdir(), "crs-replay-"));
  const datasetDir = join(root, "dataset");
  const recordedDir = join(root, "recorded");
  const vulnerable = makeSample({
    sample_id: "s1",
    labels: [{ path: "src/app.py", startLine: 2, endLine: 2, cwe: "CWE-78" }],
  });
  const safe = makeSample({
    sample_id: "s2",
    cwe: null,
    paired_safe: true,
    labels: [],
    after: "print('safe')\n",
  });
  await writeDataset(datasetDir, [vulnerable, safe]);
  await writeRecorded(recordedDir, "s1", [
    result("semgrep", [finding("semgrep", "src/app.py", 2, 2)]),
    result("aor", [finding("aor", "src/app.py", 2, 3, { confidence: 0.5 })]),
  ]);
  await writeRecorded(recordedDir, "s2", [
    result("semgrep", []),
    result("aor", [], {
      status: "degraded",
      coverage: { filesCovered: 0, filesUnknown: 1 },
      tokens: null,
    }),
  ]);
  const loaded = await loadDataset(datasetDir);
  return { root, datasetDir, recordedDir, samples: loaded.samples };
}

describe("dataset and recording loaders", () => {
  it("loads manifest samples and recorded source results", async () => {
    const fixture = await prepare();
    expect(fixture.samples.map((sample) => sample.sample_id)).toEqual(["s1", "s2"]);
    const recorded = await loadRecorded(fixture.recordedDir);
    expect(recorded.s1!.map((entry) => entry.source)).toEqual(["semgrep", "aor"]);
    expect(recorded.s1![0]!.status).toBe("ok");
  });
});

describe("runBaseline", () => {
  it("marks B0 as skipped and not applicable in replay", async () => {
    const fixture = await prepare();
    const records = await runBaseline({
      baseline: "B0",
      config: makeConfig(),
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      runId: "run-B0",
      datasetRoot: fixture.datasetDir,
    });
    expect(records).toHaveLength(2);
    for (const record of records) {
      expect(record.status).toBe("skipped");
      expect(record.outcome).toBe("none");
      expect(record.error).toBe("B0 not applicable in replay");
      expect(record.sources).toEqual([]);
      expect(record.findings_merged).toEqual([]);
      expect(record.disposition.skipReason).toBe("no_change");
      expect(record.findings_raw_ref).toBe("raw/run-B0.json");
      expect(record.config_hash).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  it("assembles B4g with both sources and a replay ChangeEvent", async () => {
    const fixture = await prepare();
    const config = makeConfig();
    const records = await runBaseline({
      baseline: "B4g",
      config,
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      runId: "run-B4g",
      datasetRoot: fixture.datasetDir,
    });
    const record = records[0]!;
    expect(record.mode).toBe("replay");
    expect(record.baseline).toBe("B4g");
    expect(record.tier).toBe(2);
    expect(record.sources.map((source) => source.source)).toEqual(["semgrep", "aor"]);
    expect(record.findings_merged.length).toBeGreaterThan(0);
    expect(record.change_event).toMatchObject({
      sessionId: "replay",
      rootCallId: "s1",
      phase: "post",
      trigger: "write",
      diffProvenance: "observed",
      files: ["src/app.py"],
    });
    expect(record.config_hash).toBe(effectiveConfigHash(config, "B4g"));
    expect(record.cache).toBe("cold");
    expect(record.tokens.total).toBe(120);
    expect(record.repo).toEqual({ rev: fixture.datasetDir, files_scanned: 2 });
  });

  it("assembles B1, B2 and B4 with their ladder-specific sources", async () => {
    const fixture = await prepare();
    const base = {
      config: makeConfig(),
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      datasetRoot: fixture.datasetDir,
    };
    const b1 = await runBaseline({ ...base, baseline: "B1", runId: "r-B1" });
    const b2 = await runBaseline({ ...base, baseline: "B2", runId: "r-B2" });
    const b4 = await runBaseline({ ...base, baseline: "B4", runId: "r-B4" });
    expect(b1[0]!.sources.map((source) => source.source)).toEqual(["semgrep"]);
    expect(b2[0]!.sources.map((source) => source.source)).toEqual(["aor"]);
    expect(b4[0]!.tier).toBe(0);
    expect(b4[0]!.sources.map((source) => source.source)).toEqual(["semgrep"]);
    expect(b4[0]!.config_hash).not.toBe(b1[0]!.config_hash);
  });

  it("reports unknown coverage and partial status from degraded recordings", async () => {
    const fixture = await prepare();
    const records = await runBaseline({
      baseline: "B4g",
      config: makeConfig(),
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      runId: "run-unknown",
      datasetRoot: fixture.datasetDir,
    });
    const safe = records.find((record) => record.sample === "s2")!;
    expect(safe.status).toBe("partial");
    expect(unknownCoverage(records).filesUnknown).toBe(1);
    expect(sourceErrorRates(records).aor).toMatchObject({ total: 2, degraded: 1, ok: 1 });
  });

  it("labels cache as cold, warm or null on request", async () => {
    const fixture = await prepare();
    const common = {
      baseline: "B1" as const,
      config: makeConfig(),
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      runId: "run-cache",
      datasetRoot: fixture.datasetDir,
    };
    expect((await runBaseline(common))[0]!.cache).toBe("cold");
    expect((await runBaseline({ ...common, cache: "warm" }))[0]!.cache).toBe("warm");
    expect((await runBaseline({ ...common, cache: null }))[0]!.cache).toBeNull();
  });

  it("names persisted run files by config hash and rejects stale hashes", async () => {
    const fixture = await prepare();
    const outDir = join(fixture.root, "out");
    const first = makeConfig();
    const second = makeConfig({ version: "2.0.0" });
    const firstHash = effectiveConfigHash(first, "B1");
    const secondHash = effectiveConfigHash(second, "B1");
    expect(firstHash).not.toBe(secondHash);
    const common = {
      baseline: "B1" as const,
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      runId: "hash-run",
      datasetRoot: fixture.datasetDir,
      outDir,
    };
    await runBaseline({ ...common, config: first });
    await runBaseline({ ...common, config: second });
    const files = await readdir(join(outDir, "runs", "hash-run"));
    expect(new Set(files)).toEqual(new Set([`runs.${firstHash}.jsonl`, `runs.${secondHash}.jsonl`]));
    const persisted = await readJsonl<RunRecord>(join(outDir, "runs", "hash-run", `runs.${secondHash}.jsonl`));
    expect(persisted.every((row) => row.config_hash === secondHash)).toBe(true);
  });
});

describe("runReplay", () => {
  it("writes the ladder records and the pairing table", async () => {
    const fixture = await prepare();
    const result = await runReplay({
      config: makeConfig(),
      samples: fixture.samples,
      recordedDir: fixture.recordedDir,
      runId: "exp",
      outDir: fixture.root,
      datasetRoot: fixture.datasetDir,
      baselines: ["B0", "B1", "B4g"],
    });
    expect(result.runs).toHaveLength(6);
    expect(result.hashes).toHaveLength(3);
    const rootDir = join(fixture.root, "runs", "exp");
    const runs = await readJsonl<RunRecord>(join(rootDir, "runs.jsonl"));
    expect(runs).toHaveLength(6);
    const pairing = await readJsonl<PairingRow>(join(rootDir, "pairing.jsonl"));
    expect(pairing).toHaveLength(3);
    const keys = pairing.map((row) => `${row.run_id}\u0000${row.gt_id}`);
    expect(new Set(keys).size).toBe(keys.length);
    const b0 = pairing.find((row) => row.run_id === "exp-B0")!;
    expect(b0).toMatchObject({ merged_id: null, overlap: 0, union: 0 });
    const b4g = pairing.find((row) => row.run_id === "exp-B4g")!;
    expect(b4g.merged_id).not.toBeNull();
    expect(b4g.overlap).toBe(1);
    const configFile = await readFile(join(rootDir, "B4g", "config.json"), "utf8");
    expect(JSON.parse(configFile).config.baseline).toBe("B4g");
  });
});
