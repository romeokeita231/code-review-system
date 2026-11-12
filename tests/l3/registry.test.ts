import { describe, expect, it } from "vitest";
import { createRegistrySource, type RegistryFetch } from "../../src/l3/index.js";
import { makeConfig, makeInput } from "./support.js";

function fetchMap(table: Record<string, number>): { impl: RegistryFetch; calls: string[] } {
  const calls: string[] = [];
  const impl: RegistryFetch = async (url) => {
    calls.push(url);
    const name = url.includes("registry.npmjs.org")
      ? decodeURIComponent(url.slice("https://registry.npmjs.org/".length))
      : decodeURIComponent(url.slice("https://pypi.org/pypi/".length, -"/json".length));
    return { status: table[name] ?? 500 };
  };
  return { impl, calls };
}

const packageJson = `{
  "dependencies": {
    "left-pad": "^1.0.0",
    "lodash": "^4.17.0"
  },
  "devDependencies": {
    "vitest": "^2.1.8"
  }
}
`;

describe("RegistrySource", () => {
  it("flags a missing npm package and ignores an existing one", async () => {
    const { impl, calls } = fetchMap({ "left-pad": 404, lodash: 200, vitest: 200 });
    const config = makeConfig();
    const source = createRegistrySource(config, { root: process.cwd(), fetchImpl: impl });
    const result = await source.review(
      makeInput(config, ["package.json"], { "package.json": packageJson }),
    );

    expect(result.status).toBe("ok");
    expect(result.findings).toHaveLength(1);
    const found = result.findings[0]!;
    expect(found.file).toBe("package.json");
    expect(found.startLine).toBe(3);
    expect(found.endLine).toBe(3);
    expect(found.severity).toBe(2);
    expect(found.confidence).toBe(0.9);
    expect(found.cwe).toBeNull();
    expect(found.evidence).toBe("package not found: left-pad");
    expect(result.coverage).toEqual({ filesCovered: 1, filesUnknown: 0 });
    expect(calls).toHaveLength(3);
  });

  it("only considers added lines when a diff is present", async () => {
    const diff = [
      "--- a/package.json",
      "+++ b/package.json",
      "@@ -1,5 +1,6 @@",
      " {",
      '   "dependencies": {',
      '+    "left-pad": "^1.0.0",',
      '     "lodash": "^4.17.0"',
      "   }",
      " }",
    ].join("\n");
    const { impl, calls } = fetchMap({ "left-pad": 404, lodash: 404 });
    const config = makeConfig();
    const source = createRegistrySource(config, { root: process.cwd(), fetchImpl: impl });
    const result = await source.review(
      makeInput(config, ["package.json"], { "package.json": packageJson }, Date.now() + 60000, diff),
    );

    expect(result.findings).toHaveLength(1);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain("left-pad");
  });

  it("flags a missing pypi requirement", async () => {
    const { impl } = fetchMap({ "made-up-package": 404, flask: 200 });
    const config = makeConfig();
    const source = createRegistrySource(config, { root: process.cwd(), fetchImpl: impl });
    const result = await source.review(
      makeInput(config, ["requirements.txt"], {
        "requirements.txt": "flask>=2.0\nmade-up-package==0.0.1\n",
      }),
    );

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.evidence).toBe("package not found: made-up-package");
    expect(result.findings[0]?.startLine).toBe(2);
  });

  it("fails open on network errors", async () => {
    const impl: RegistryFetch = async () => {
      throw new Error("network down");
    };
    const config = makeConfig();
    const source = createRegistrySource(config, { root: process.cwd(), fetchImpl: impl });
    const result = await source.review(
      makeInput(config, ["package.json"], { "package.json": packageJson }),
    );

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("network");
    expect(result.findings).toEqual([]);
  });

  it("fails open on timeout", async () => {
    const impl: RegistryFetch = (_url, init) =>
      new Promise((_resolve, reject) => {
        init.signal.addEventListener("abort", () => reject(new Error("aborted")));
      });
    const config = makeConfig({ registry: { timeoutMs: 5 } });
    const source = createRegistrySource(config, { root: process.cwd(), fetchImpl: impl });
    const result = await source.review(
      makeInput(config, ["package.json"], { "package.json": packageJson }),
    );

    expect(result.status).toBe("degraded");
    expect(result.errorKind).toBe("timeout");
    expect(result.findings).toEqual([]);
  });
});
