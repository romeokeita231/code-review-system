import { describe, expect, it } from "vitest";
import { CrgTriage, analyzeStatic, createCrgTriage } from "../../src/l3/index.js";
import { ScriptedRunner, commandResult, makeConfig, makeEvent } from "./support.js";

describe("CrgTriage", () => {
  it("maps a successful payload into a triage analysis", () => {
    const analysis = analyzeStatic(
      ["src/changed.ts"],
      {
        status: "ok",
        impacted_files: ["src/changed.ts", "src/other.ts"],
        impacted_file_count: 2,
        total_impacted: 7,
        truncated: false,
        unresolved_call_sites: 0,
      },
      "C:/repo",
    );

    expect(analysis).toEqual({
      changedFiles: ["src/changed.ts"],
      impactedFiles: 2,
      impactedNodes: 7,
      truncated: false,
      unresolvedCallSites: 0,
      indexReady: true,
      indexStale: false,
    });
  });

  it("propagates truncation and unresolved call sites", () => {
    const analysis = analyzeStatic(["a.ts"], {
      status: "ok",
      impacted_files: ["a.ts", "b.ts"],
      total_impacted: 30,
      truncated: true,
      unresolved_call_sites: 4,
    });

    expect(analysis.truncated).toBe(true);
    expect(analysis.unresolvedCallSites).toBe(4);
    expect(analysis.impactedNodes).toBe(30);
  });

  it("marks partial indexes as stale and truncated", () => {
    const analysis = analyzeStatic(["a.ts"], { status: "partial", total_impacted: 3 });
    expect(analysis.indexStale).toBe(true);
    expect(analysis.truncated).toBe(true);
  });

  it("queries out of process with a bounded deadline", async () => {
    const runner = new ScriptedRunner(() =>
      commandResult({
        status: "ok",
        impacted_files: ["src/a.ts", "src/b.ts"],
        total_impacted: 5,
        truncated: false,
        unresolved_call_sites: 0,
      }),
    );
    const triage = createCrgTriage(makeConfig(), { root: "C:/repo", runner });
    const analysis = await triage.analyze(makeEvent(["src/a.ts"]), Date.now() + 5000);

    expect(runner.calls[0]?.args).toContain("-m");
    expect(runner.calls[0]?.args).toContain("crg");
    expect(runner.calls[0]?.timeoutMs).toBeLessThanOrEqual(300);
    expect(analysis.impactedFiles).toBe(2);
    expect(analysis.indexReady).toBe(true);
  });

  it("degrades on timeout", async () => {
    const runner = new ScriptedRunner(() => commandResult("", { timedOut: true, exitCode: -1 }));
    const triage = new CrgTriage(makeConfig(), { root: "C:/repo", runner });
    const analysis = await triage.analyze(makeEvent(["src/a.ts"]), Date.now() + 5000);

    expect(analysis).toEqual({
      changedFiles: ["src/a.ts"],
      impactedFiles: 1,
      impactedNodes: 0,
      truncated: true,
      unresolvedCallSites: 0,
      indexReady: false,
      indexStale: false,
    });
  });

  it("degrades on failure and caches readiness per root", async () => {
    const runner = new ScriptedRunner(() => {
      throw new Error("no index");
    });
    const triage = new CrgTriage(makeConfig(), { root: "C:/repo", runner });

    const first = await triage.analyze(makeEvent(["src/a.ts"]), Date.now() + 5000);
    const second = await triage.analyze(makeEvent(["src/a.ts"]), Date.now() + 5000);

    expect(first.indexReady).toBe(false);
    expect(second.indexReady).toBe(false);
    expect(runner.calls).toHaveLength(1);
  });
});
