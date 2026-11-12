import { describe, expect, it } from "vitest";
import { createSources, createTriage } from "../../src/l3/index.js";
import { FakeSource, degradedResult, okResult, timeoutResult } from "../support/fake-source.js";
import { finding, makeConfig, makeInput } from "./support.js";

describe("FakeSource", () => {
  it("returns scripted results in order and repeats the last one", async () => {
    const source = new FakeSource("semgrep", [
      okResult("semgrep", [finding()]),
      timeoutResult("semgrep"),
    ]);
    const config = makeConfig();
    const input = makeInput(config, ["a.py"], { "a.py": "x = 1\n" });

    expect((await source.review(input)).status).toBe("ok");
    expect((await source.review(input)).status).toBe("timeout");
    expect((await source.review(input)).status).toBe("timeout");
  });

  it("falls back to degraded when the script is empty", async () => {
    const source = new FakeSource("aor", []);
    const result = await source.review(makeInput(makeConfig(), ["a.py"], { "a.py": "x = 1\n" }));
    expect(result).toEqual(degradedResult("aor"));
  });
});

describe("factories", () => {
  it("assembles enabled sources in fixed order", () => {
    const sources = createSources(makeConfig(), { root: process.cwd() });
    expect(sources.map((source) => source.name)).toEqual(["semgrep", "aor", "registry"]);
  });

  it("omits disabled sources", () => {
    const config = makeConfig({
      semgrep: { enabled: false },
      aor: { enabled: false },
      registry: { enabled: false },
    });
    expect(createSources(config, { root: process.cwd() })).toEqual([]);
  });

  it("only creates triage when enabled", () => {
    expect(createTriage(makeConfig(), { root: process.cwd() })).not.toBeNull();
    expect(createTriage(makeConfig({ triage: { enabled: false } }), { root: process.cwd() })).toBeNull();
    expect(createTriage(makeConfig({ crg: { enabled: false } }), { root: process.cwd() })).toBeNull();
  });
});
