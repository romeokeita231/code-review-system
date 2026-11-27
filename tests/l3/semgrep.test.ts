import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { contentSha256 } from "../../src/config/index.js";
import { createSemgrepSource } from "../../src/l3/index.js";
import { ScriptedRunner, commandResult, makeConfig, makeInput } from "./support.js";

const fixture = JSON.parse(
  readFileSync(new URL("../../research/semgrep-bench/_payload_py.json", import.meta.url), "utf8"),
) as { doc: Record<string, unknown> & { results: Array<Record<string, unknown>>; paths: { scanned: string[] }; errors: unknown[] } };

function cloneDoc(): typeof fixture.doc {
  return structuredClone(fixture.doc);
}

function runnerFor(doc: unknown): ScriptedRunner {
  return new ScriptedRunner((request) => {
    const payload = structuredClone(doc) as {
      results?: Array<Record<string, unknown>>;
    };
    for (const result of payload.results ?? []) {
      result["path"] = `${request.cwd}/target.py`;
    }
    return commandResult(payload);
  });
}

describe("SemgrepSource", () => {
  it("parses the research payload into findings", async () => {
    const runner = runnerFor(cloneDoc());
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner });
    const result = await source.review(
      makeInput(makeConfig(), ["target.py"], { "target.py": "import subprocess\n" }),
    );

    expect(runner.calls).toHaveLength(1);
    expect(runner.calls[0]?.args).toContain("--no-git-ignore");
    expect(runner.calls[0]?.args).not.toContain("--quiet");
    expect(runner.calls[0]?.args).toContain("--x-semgrepignore-filename");
    expect(result.status).toBe("ok");
    expect(result.findings).toHaveLength(3);
    expect(result.findings[0]).toMatchObject({
      file: "target.py",
      startLine: 5,
      endLine: 5,
      severity: 3,
      confidence: 0.3,
      source: "semgrep",
      cwe: "CWE-78",
    });
    expect(result.findings[0]?.evidence).toBeNull();
    expect(result.coverage).toEqual({ filesCovered: 1, filesUnknown: 0 });
    expect(result.tokens).toBeNull();
  });

  it("degrades when paths.scanned is not exactly one", async () => {
    const doc = cloneDoc();
    doc.paths.scanned.push("other.py");
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner: runnerFor(doc) });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("paths_scanned");
    expect(result.findings).toEqual([]);
  });

  it("ignores results from non-core engines", async () => {
    const doc = cloneDoc();
    for (const result of doc.results) {
      const extra = result["extra"] as Record<string, unknown>;
      extra["engine"] = "osemgrep";
    }
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner: runnerFor(doc) });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("ok");
    expect(result.findings).toEqual([]);
  });

  it("degrades when no engine field is present", async () => {
    const doc = cloneDoc();
    for (const result of doc.results) {
      const extra = result["extra"] as Record<string, unknown>;
      extra["engine_kind"] = undefined;
    }
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner: runnerFor(doc) });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("engine_contract");
  });

  it("fails open on oversized files without spawning", async () => {
    const runner = new ScriptedRunner(() => commandResult({}));
    const config = makeConfig({ sMax: { python: 4 } });
    const source = createSemgrepSource(config, { root: process.cwd(), runner });
    const result = await source.review(makeInput(config, ["target.py"], { "target.py": "print(1)\n" }));

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("file_too_large");
    expect(result.findings).toEqual([]);
    expect(runner.calls).toHaveLength(0);
  });

  it("returns timeout without throwing", async () => {
    const runner = new ScriptedRunner(() => commandResult("", { timedOut: true, exitCode: -1 }));
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("timeout");
    expect(result.findings).toEqual([]);
  });

  it("returns error when the runner throws", async () => {
    const runner = new ScriptedRunner(() => {
      throw new Error("spawn failed");
    });
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("error");
    expect(result.errorKind).toBe("spawn_error");
  });

  it("degrades when errors is non-empty", async () => {
    const doc = cloneDoc();
    doc.errors.push({ message: "parse error" });
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner: runnerFor(doc) });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("scan_errors");
  });

  it("degrades when a result lacks required fields", async () => {
    const doc = cloneDoc();
    doc.results[0]!["check_id"] = undefined;
    const source = createSemgrepSource(makeConfig(), { root: process.cwd(), runner: runnerFor(doc) });
    const result = await source.review(makeInput(makeConfig(), ["target.py"], { "target.py": "x = 1\n" }));

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("result_shape");
  });

  it("accepts the pinned rules whichever line endings the checkout produced", async () => {
    // The pin is a claim about the rules, not about a checkout. It used to be
    // `sha256` of the bytes on disk, which made it true on exactly one platform:
    // the first CI run this repository ever had degraded every semgrep test with
    // `rules_sha256`, and the degraded path reports no findings, so the only
    // visible symptom was that the scanner had gone quiet.
    const rules = readFileSync(
      new URL("../../research/semgrep-bench/snapshot/py_block.yaml", import.meta.url),
      "utf8",
    );
    const pinned = makeConfig().sources.semgrep.subsets[0]!;
    expect(pinned.sha256).toBe(contentSha256(rules));

    const dir = mkdtempSync(join(tmpdir(), "crs-rules-"));
    try {
      const forms: Array<[string, string]> = [
        ["crlf.yaml", rules.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n")],
        ["lf.yaml", rules.replace(/\r\n/g, "\n")],
      ];
      for (const [name, text] of forms) {
        const file = join(dir, name);
        writeFileSync(file, text);
        const config = makeConfig({ semgrep: { subsets: [{ ...pinned, path: file }] } });
        const runner = runnerFor(cloneDoc());
        const source = createSemgrepSource(config, { root: process.cwd(), runner });
        const result = await source.review(makeInput(config, ["target.py"], { "target.py": "import subprocess\n" }));

        expect(result.status, `${name} should scan`).toBe("ok");
        expect(runner.calls, `${name} should reach semgrep`).toHaveLength(1);
      }
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
