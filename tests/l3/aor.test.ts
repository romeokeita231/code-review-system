import { describe, expect, it } from "vitest";
import { createAorSource } from "../../src/l3/index.js";
import { ScriptedRunner, commandResult, makeConfig, makeInput } from "./support.js";

const successEnvelope = {
  status: "success",
  summary: {
    files_reviewed: 1,
    comments: 3,
    total_tokens: 21344,
    input_tokens: 18012,
    output_tokens: 3332,
  },
  comments: [
    {
      path: "src/app.py",
      content: "SQL injection via string interpolation",
      start_line: 10,
      end_line: 12,
      existing_code: "cur.execute(f\"SELECT * FROM t WHERE id = {uid}\")",
      severity: "critical",
    },
    {
      path: "src/app.py",
      content: "file level comment",
      start_line: 0,
      end_line: 0,
      existing_code: "import os",
    },
    {
      path: "src/app.py",
      content: "no evidence",
      start_line: 4,
      end_line: 5,
    },
  ],
};

describe("AorSource", () => {
  it("filters comments and reports the drop rate", async () => {
    const runner = new ScriptedRunner(() => commandResult(successEnvelope));
    const config = makeConfig();
    const source = createAorSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["src/app.py"], { "src/app.py": "x = 1\n" }));

    expect(result.status).toBe("ok");
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]).toMatchObject({
      file: "src/app.py",
      startLine: 10,
      endLine: 12,
      severity: 3,
      confidence: 0.6,
      cwe: null,
    });
    expect(result.findings[0]?.evidence).toBe("cur.execute(f\"SELECT * FROM t WHERE id = {uid}\")");
    expect(result.errorKind).toBe("dropped:2/3");
    expect(result.tokens).toBe(21344);
    expect(result.coverage).toEqual({ filesCovered: 1, filesUnknown: 0 });
  });

  it("uses concurrency 2, a tightened timeout and no effort flag", async () => {
    const runner = new ScriptedRunner(() => commandResult(successEnvelope));
    const source = createAorSource(makeConfig(), { root: process.cwd(), runner });
    await source.review(makeInput(makeConfig(), ["src/app.py"], { "src/app.py": "x = 1\n" }));

    const args = runner.calls[0]?.args ?? [];
    expect(args).toContain("--concurrency");
    expect(args[args.indexOf("--concurrency") + 1]).toBe("2");
    expect(args).toContain("--timeout");
    expect(args[args.indexOf("--timeout") + 1]).not.toBe("15");
    expect(args).toContain("--no-summary");
    expect(args).not.toContain("--effort");
    expect(args).toContain("--path");
    expect(args[args.indexOf("--path") + 1]).toBe("src/app.py");
  });

  it("treats budget_exceeded as partial coverage", async () => {
    const runner = new ScriptedRunner(() =>
      commandResult({
        status: "success",
        summary: { files_reviewed: 0, budget_exceeded: true, total_tokens: 500 },
        comments: [],
      }),
    );
    const config = makeConfig();
    const source = createAorSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["src/app.py"], { "src/app.py": "x = 1\n" }));

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toContain("budget_exceeded");
    expect(result.coverage.filesCovered).toBe(0);
    expect(result.coverage.filesUnknown).toBeGreaterThan(0);
  });

  it("reports failed envelopes as errors with no findings", async () => {
    const runner = new ScriptedRunner(() => commandResult({ status: "failed", message: "boom" }));
    const config = makeConfig();
    const source = createAorSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["src/app.py"], { "src/app.py": "x = 1\n" }));

    expect(result.status).toBe("error");
    expect(result.errorKind).toBe("failed");
    expect(result.findings).toEqual([]);
  });

  it("reports half-parsed JSON as an error", async () => {
    const runner = new ScriptedRunner(() => commandResult('{"status":"success"'));
    const config = makeConfig();
    const source = createAorSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["src/app.py"], { "src/app.py": "x = 1\n" }));

    expect(result.status).toBe("error");
    expect(result.errorKind).toBe("half_parsed");
    expect(result.findings).toEqual([]);
  });

  it("reports outer timeout as timeout", async () => {
    const runner = new ScriptedRunner(() => commandResult("", { timedOut: true, exitCode: -1 }));
    const config = makeConfig();
    const source = createAorSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["src/app.py"], { "src/app.py": "x = 1\n" }));

    expect(result.status).toBe("timeout");
    expect(result.findings).toEqual([]);
  });

  it("drops comments with empty existing_code", async () => {
    const runner = new ScriptedRunner(() =>
      commandResult({
        status: "success",
        summary: { files_reviewed: 1, comments: 1, total_tokens: 10 },
        comments: [{ path: "src/app.py", content: "issue", start_line: 2, end_line: 3, existing_code: "  " }],
      }),
    );
    const config = makeConfig();
    const source = createAorSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["src/app.py"], { "src/app.py": "x = 1\n" }));

    expect(result.findings).toEqual([]);
    expect(result.errorKind).toBe("dropped:1/1");
  });
});
