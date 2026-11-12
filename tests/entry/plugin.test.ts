import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import type {
  CalibrationArtifact,
  Finding,
  SignalSource,
  SourceResult,
} from "../../src/contracts/index.js";
import { parseConfig } from "../../src/config/index.js";
import { DshAdapter } from "../../src/l1/index.js";
import { ConclusionCache, ledgerFor } from "../../src/l2/index.js";
import {
  apply,
  correctionContext,
  createRuntime,
  name,
  postExecute,
  preExecute,
  type HookExec,
  type PluginContext,
  type PluginRuntime,
} from "../../src/entry/plugin.js";

const artifact: CalibrationArtifact = {
  version: "calib-test",
  pPrior: 0.3,
  shrinkageN0: 10,
  pMax: 0.95,
  fitRoot: "fitroot",
  grids: [
    { source: "semgrep", category: "CWE-78", n: 40, points: [{ rawLow: 0.5, rawHigh: 1, p: 0.95 }] },
    { source: "aor", category: "CWE-79", n: 40, points: [{ rawLow: 0.5, rawHigh: 1, p: 0.85 }] },
  ],
  thresholds: { global: { block: 0.9, warn: 0.7 }, perCategory: {}, skipped: [] },
};

const finding = (over: Partial<Finding> = {}): Finding => ({
  file: "src/demo/app.py",
  startLine: 3,
  endLine: 3,
  severity: 3,
  confidence: 0.95,
  source: "semgrep",
  cwe: "CWE-78",
  evidence: "os.system(cmd)",
  rawId: "command-injection-os-system\u0000src/demo/app.py\u00003\u00003",
  ...over,
});

const ok = (source: SourceResult["source"], findings: Finding[]): SourceResult => ({
  source,
  status: "ok",
  findings,
  coverage: { filesCovered: 1, filesUnknown: 0 },
  tokens: null,
  latencyMs: 1,
  errorKind: null,
});

const fixed = (source: SignalSource["name"], result: SourceResult): SignalSource => ({
  name: source,
  async review() {
    return result;
  },
});

function tempRuntime(sources: SignalSource[]): PluginRuntime {
  const dir = mkdtempSync(join(tmpdir(), "crs-plugin-"));
  const config = parseConfig(JSON.parse(readFileSync("configs/b4g.json", "utf8")));
  config.sources.registry.enabled = false;
  return {
    config,
    artifact,
    sources,
    triage: null,
    adapter: new DshAdapter(
      { cwd: () => process.cwd(), readFile: async () => "" },
      () => "crs-test",
    ),
    ledger: ledgerFor(config),
    guards: new Map(),
    cache: new ConclusionCache(config.budgets.cacheTtlMs),
    jsonlPath: join(dir, "review.jsonl"),
  };
}

const exec = (over: Partial<HookExec> = {}): HookExec => ({
  name: "write",
  callId: "call-1",
  rootCallId: "call-1",
  arguments: { file_path: join(process.cwd(), "src/demo/app.py"), content: "print(1)\n" },
  agent: { session: { id: "sess-1" } },
  ...over,
});

describe("plugin entry", () => {
  it("declares a stable Cordis plugin name", () => {
    expect(name).toBe("code-review-system");
  });

  it("fails loudly when the config path is missing", () => {
    expect(() => apply({ on: vi.fn() }, { configPath: "configs/does-not-exist.json" })).toThrow(
      /config not found/,
    );
  });

  it("fails loudly when no config object is supplied", () => {
    expect(() => apply({ on: vi.fn() }, undefined as never)).toThrow(/missing plugin config/);
  });

  it("registers both tool hooks", () => {
    const on = vi.fn();
    apply({ on }, { configPath: "configs/b4g.json", artifactPath: "artifacts/calibration.json" });
    const events = on.mock.calls.map((call) => call[0]);
    expect(events).toEqual(["tools/pre-execute", "tools/post-execute"]);
  });

  it("fails open when the config is unreadable at runtime", async () => {
    const dir = mkdtempSync(join(tmpdir(), "crs-bad-"));
    const path = join(dir, "broken.json");
    writeFileSync(path, "{ not json", "utf8");
    const handlers = new Map<string, (...args: never[]) => unknown>();
    apply({ on: (event, handler) => handlers.set(event, handler) }, { configPath: path });
    const next = vi.fn(async () => ({ kind: "allow" }));
    const pre = handlers.get("tools/pre-execute") as never as (
      exec: HookExec,
      next: () => Promise<unknown>,
    ) => Promise<unknown>;
    await expect(pre(exec(), next)).resolves.toEqual({ kind: "allow" });
    expect(next).toHaveBeenCalledTimes(1);
  });

  it("denies a pre write on a blocking semgrep finding", async () => {
    const runtime = tempRuntime([fixed("semgrep", ok("semgrep", [finding()]))]);
    const decision = await preExecute(runtime, exec());
    expect(decision.kind).toBe("deny");
    if (decision.kind !== "deny") return;
    expect(decision.reason).toContain("[CRS-BLOCK]");
    expect(decision.reason).toContain("CWE-78");
  });

  it("allows a pre write when sources are degraded", async () => {
    const runtime = tempRuntime([
      fixed("semgrep", {
        source: "semgrep",
        status: "degraded",
        findings: [],
        coverage: { filesCovered: 0, filesUnknown: 1 },
        tokens: null,
        latencyMs: 1,
        errorKind: "degraded",
      }),
    ]);
    expect((await preExecute(runtime, exec())).kind).toBe("allow");
  });

  it("injects a labelled CRS-WARN context after a semantic finding", async () => {
    const runtime = tempRuntime([
      fixed("semgrep", ok("semgrep", [])),
      fixed(
        "aor",
        ok("aor", [
          finding({ source: "aor", cwe: "CWE-79", evidence: "unescaped input", rawId: "aor-1" }),
        ]),
      ),
    ]);
    const outcome = await postExecute(runtime, exec(), {
      value: { before: "", after: "print(1)\n" },
    });
    expect(outcome.correction).not.toBeNull();
    const text = outcome.correction?.content[0]?.text ?? "";
    expect(text).toContain("[CRS-WARN]");
    expect(text).toContain("CWE-79");
    expect(outcome.correction?.source.kind).toBe("code-review-system");
    expect(outcome.correction?.source.form).toBe("notice");
    expect(outcome.correction?.role).toBe("user");
    expect(outcome.correction?.id).toMatch(/[0-9a-f-]{16,}/);
  });

  it("does not inject a context for a clean post write", async () => {
    const runtime = tempRuntime([fixed("semgrep", ok("semgrep", []))]);
    const outcome = await postExecute(runtime, exec(), {
      value: { before: "", after: "print(1)\n" },
    });
    expect(outcome.correction).toBeNull();
  });
});

describe("correctionContext", () => {
  it("bounds the notice summary while keeping the full text", () => {
    const message = correctionContext(`[CRS-WARN] ${"x".repeat(400)}`);
    expect(message.source.summary.length).toBeLessThanOrEqual(120);
    expect(message.content[0]?.text.length).toBeGreaterThan(400);
  });
});

describe("createRuntime", () => {
  it("rejects a config whose calibration artifact is missing", async () => {
    const dir = mkdtempSync(join(tmpdir(), "crs-rt-"));
    const configPath = join(dir, "b4.json");
    writeFileSync(
      configPath,
      JSON.stringify({
        ...JSON.parse(readFileSync("configs/b4.json", "utf8")),
        calibration: { artifactPath: join(dir, "missing.json"), version: "calib-v1" },
      }),
      "utf8",
    );
    await expect(createRuntime({ configPath })).rejects.toThrow(/calibration artifact is missing/);
  });
});
