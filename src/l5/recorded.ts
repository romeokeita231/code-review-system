import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { SourceResult, type SignalSource, type SourceName } from "../contracts/index.js";

const SOURCE_ORDER: Record<SourceName, number> = {
  semgrep: 0,
  aor: 1,
  crg: 2,
  registry: 3,
};

export type RecordedBySample = Record<string, SourceResult[]>;

export class RecordedSource implements SignalSource {
  readonly name: SourceName;
  private readonly result: SourceResult;

  constructor(result: SourceResult) {
    this.result = result;
    this.name = result.source;
  }

  async review(): Promise<SourceResult> {
    return structuredClone(this.result);
  }
}

export function missingRecording(source: SourceName): SourceResult {
  return {
    source,
    status: "error",
    findings: [],
    coverage: { filesCovered: 0, filesUnknown: 0 },
    tokens: null,
    latencyMs: 0,
    errorKind: "missing_recording",
  };
}

export async function loadRecorded(dir: string): Promise<RecordedBySample> {
  const recorded: RecordedBySample = {};
  let sampleDirs: string[];
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    sampleDirs = entries.filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  } catch {
    return recorded;
  }
  for (const sampleId of sampleDirs) {
    const sampleDir = join(dir, sampleId);
    let files: string[];
    try {
      files = (await readdir(sampleDir)).filter((file) => file.endsWith(".json")).sort();
    } catch {
      continue;
    }
    const results: SourceResult[] = [];
    for (const file of files) {
      const raw = JSON.parse(await readFile(join(sampleDir, file), "utf8")) as unknown;
      results.push(SourceResult.parse(raw));
    }
    results.sort((a, b) => SOURCE_ORDER[a.source] - SOURCE_ORDER[b.source]);
    recorded[sampleId] = results;
  }
  return recorded;
}
