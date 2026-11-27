import type {
  ChangeEvent,
  Finding,
  RunConfig,
  SourceReviewInput,
} from "../../src/contracts/index.js";
import type { CommandRequest, CommandResult, CommandRunner } from "../../src/l3/semgrep.js";

export interface ConfigOverrides {
  semgrep?: Partial<RunConfig["sources"]["semgrep"]>;
  aor?: Partial<RunConfig["sources"]["aor"]>;
  crg?: Partial<RunConfig["sources"]["crg"]>;
  registry?: Partial<RunConfig["sources"]["registry"]>;
  triage?: Partial<RunConfig["triage"]>;
  sMax?: Partial<RunConfig["sMax"]>;
}

export function makeConfig(overrides: ConfigOverrides = {}): RunConfig {
  return {
    version: "v1",
    mode: "replay",
    baseline: "B4",
    sources: {
      semgrep: {
        enabled: true,
        command: "semgrep",
        osemgrepCommand: "osemgrep",
        version: "1.184.0",
        fullBlockMaxBytes: 102400,
        subsets: [
          {
            id: "py-block",
            path: "research/semgrep-bench/snapshot/py_block.yaml",
            sha256: "ab8998b6128c0ab94bf199a67676f870553e5f31b436e8a41cf0dc78ba4ab375",
            langs: ["python"],
            blockRules: ["command-injection-os-system"],
          },
        ],
        ...overrides.semgrep,
      },
      aor: {
        enabled: true,
        command: "ocr",
        versionCommit: "04deca6",
        outerCapMs: 120000,
        concurrency: 2,
        timeoutPerFileMs: 60000,
        maxChunks: 4,
        preview: { enabled: false, budgetSwitchRatio: 0.6 },
        tierTokens: { tier1: 60000, tier2: 150000 },
        tier2MaxTools: 100,
        ...overrides.aor,
      },
      crg: {
        enabled: true,
        command: "code-review-graph",
        indexTimeoutMs: 300,
        ...overrides.crg,
      },
      registry: {
        enabled: true,
        command: "registry",
        timeoutMs: 1000,
        ...overrides.registry,
      },
    },
    fusionStages: { merge: true, conflict: true, calibrate: true, vote: true },
    tieBreak: "max",
    triage: {
      enabled: true,
      tier0: { filesMax: 3, nodesMax: 20 },
      tier1: { filesMax: 10, nodesMax: 100 },
      ...overrides.triage,
    },
    budgets: {
      callMs: 8000,
      turnMs: 8000,
      semgrepKillMs: 5000,
      crgQueryMs: 300,
      fusionWriteMs: 500,
      cacheTtlMs: 300000,
      maxConcurrency: 2,
    },
    thresholds: { block: 0.9, warn: 0.7 },
    weights: { single: 1, dual: 0.75 },
    prior: { pPrior: 0.1 },
    calibration: { artifactPath: "calibration.json", version: "1" },
    sMax: { python: 743188, typescript: 102400, ...overrides.sMax },
    persistence: {
      jsonlPath: "runs/runs.jsonl",
      rawDir: "runs/raw",
      turnStatePath: "runs/turn.json",
    },
  };
}

export function makeEvent(files: string[] | null, diff: string | null = null): ChangeEvent {
  return {
    id: "evt-1",
    sessionId: "sess-1",
    rootCallId: "call-1",
    phase: "post",
    trigger: "write",
    files,
    diff,
    diffProvenance: diff === null ? "none" : "observed",
    ts: 0,
  };
}

export function makeInput(
  config: RunConfig,
  files: string[],
  sourceText: Record<string, string>,
  deadline = Date.now() + 60000,
  diff: string | null = null,
): SourceReviewInput {
  return {
    event: makeEvent(files, diff),
    tier: 1,
    config,
    deadline,
    sourceText,
  };
}

export class ScriptedRunner implements CommandRunner {
  readonly calls: CommandRequest[] = [];

  private readonly handler: (request: CommandRequest) => CommandResult | Promise<CommandResult>;

  constructor(handler: (request: CommandRequest) => CommandResult | Promise<CommandResult>) {
    this.handler = handler;
  }

  async run(request: CommandRequest): Promise<CommandResult> {
    this.calls.push(request);
    return this.handler(request);
  }
}

export function commandResult(stdout: unknown, overrides: Partial<CommandResult> = {}): CommandResult {
  return {
    stdout: typeof stdout === "string" ? stdout : JSON.stringify(stdout),
    stderr: "",
    exitCode: 0,
    timedOut: false,
    ...overrides,
  };
}

export function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    file: "src/app.py",
    startLine: 1,
    endLine: 1,
    severity: 3,
    confidence: 0.8,
    source: "semgrep",
    cwe: "CWE-78",
    evidence: "eval(input())",
    rawId: "rule\u0000src/app.py\u00001\u00001",
    ...overrides,
  };
}
