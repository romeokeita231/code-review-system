import type { Finding, SignalSource, SourceName, SourceResult, SourceReviewInput } from "../contracts/index.js";

export class FakeSource implements SignalSource {
  readonly name: SourceName;

  private readonly script: Array<SourceResult | ((input: SourceReviewInput) => SourceResult)>;
  private cursor = 0;

  constructor(
    name: SourceName,
    script: Array<SourceResult | ((input: SourceReviewInput) => SourceResult)>,
  ) {
    this.name = name;
    this.script = script;
  }

  async review(input: SourceReviewInput): Promise<SourceResult> {
    if (this.script.length === 0) return degradedResult(this.name);
    const index = Math.min(this.cursor, this.script.length - 1);
    this.cursor += 1;
    const entry = this.script[index];
    if (entry === undefined) return degradedResult(this.name);
    return typeof entry === "function" ? entry(input) : entry;
  }
}

export function okResult(name: SourceName, findings: Finding[] = []): SourceResult {
  return {
    source: name,
    status: "ok",
    findings,
    coverage: { filesCovered: 1, filesUnknown: 0 },
    tokens: null,
    latencyMs: 0,
    errorKind: null,
  };
}

export function timeoutResult(name: SourceName): SourceResult {
  return {
    source: name,
    status: "timeout",
    findings: [],
    coverage: { filesCovered: 0, filesUnknown: 1 },
    tokens: null,
    latencyMs: 0,
    errorKind: "timeout",
  };
}

export function degradedResult(name: SourceName): SourceResult {
  return {
    source: name,
    status: "degraded",
    findings: [],
    coverage: { filesCovered: 0, filesUnknown: 1 },
    tokens: null,
    latencyMs: 0,
    errorKind: "degraded",
  };
}
