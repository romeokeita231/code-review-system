import type {
  Finding,
  RunConfig,
  SignalSource,
  SourceResult,
  SourceReviewInput,
} from "../contracts/index.js";

export interface RegistryResponse {
  status: number;
}

export type RegistryFetch = (
  url: string,
  init: { method: string; signal: AbortSignal },
) => Promise<RegistryResponse>;

export interface RegistryOptions {
  root: string;
  fetchImpl?: RegistryFetch;
}

interface Dependency {
  name: string;
  ecosystem: "npm" | "pypi";
  file: string;
  line: number;
}

type Check =
  | { kind: "exists" }
  | { kind: "missing" }
  | { kind: "error"; errorKind: string };

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function baseName(file: string): string {
  const parts = file.replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] ?? file;
}

function lineOf(text: string, needle: string): number {
  const index = text.split("\n").findIndex((line) => line.includes(needle));
  return index >= 0 ? index + 1 : 1;
}

function npmDependencies(file: string, text: string): Dependency[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return [];
  }
  const doc = asRecord(parsed);
  if (doc === null) return [];
  const found: Dependency[] = [];
  const seen = new Set<string>();
  for (const section of ["dependencies", "devDependencies"]) {
    const deps = asRecord(doc[section]);
    if (deps === null) continue;
    for (const name of Object.keys(deps)) {
      if (seen.has(name)) continue;
      seen.add(name);
      found.push({ name, ecosystem: "npm", file, line: lineOf(text, `"${name}"`) });
    }
  }
  return found;
}

function tomlDependencies(file: string, text: string): Dependency[] {
  const found: Dependency[] = [];
  const lines = text.split("\n");
  const pattern = /^\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~][^"']*)?["']\s*,?\s*$/;
  for (let i = 0; i < lines.length; i += 1) {
    const match = pattern.exec(lines[i] ?? "");
    if (match?.[1]) {
      found.push({ name: match[1], ecosystem: "pypi", file, line: i + 1 });
    }
  }
  return found;
}

function requirementDependencies(file: string, text: string): Dependency[] {
  const found: Dependency[] = [];
  const lines = text.split("\n");
  const pattern = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:[<>=!~][^#]*)?(?:#.*)?$/;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? "";
    if (line.trim().length === 0 || line.trim().startsWith("#")) continue;
    const match = pattern.exec(line);
    if (match?.[1]) {
      found.push({ name: match[1], ecosystem: "pypi", file, line: i + 1 });
    }
  }
  return found;
}

function addedLines(diff: string | null): Map<string, Set<number>> | null {
  if (diff === null) return null;
  const map = new Map<string, Set<number>>();
  let current: string | null = null;
  let line = 0;
  for (const raw of diff.split("\n")) {
    if (raw.startsWith("+++ ")) {
      const target = raw.slice(4).trim();
      current = target === "/dev/null" ? null : target.replace(/^b\//, "");
      if (current !== null && !map.has(current)) map.set(current, new Set());
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
    if (hunk?.[1]) {
      line = Number(hunk[1]);
      continue;
    }
    if (current === null) continue;
    if (raw.startsWith("+")) {
      map.get(current)?.add(line);
      line += 1;
    } else if (raw.startsWith("-") || raw.startsWith("\\")) {
      continue;
    } else {
      line += 1;
    }
  }
  return map;
}

function collect(text: string, file: string): Dependency[] {
  const name = baseName(file);
  if (name === "package.json") return npmDependencies(file, text);
  if (name === "pyproject.toml") return tomlDependencies(file, text);
  if (/^requirements.*\.txt$/i.test(name)) return requirementDependencies(file, text);
  return [];
}

export class RegistrySource implements SignalSource {
  readonly name = "registry" as const;

  private readonly config: RunConfig;
  private readonly fetchImpl: RegistryFetch;

  constructor(config: RunConfig, opts: RegistryOptions) {
    this.config = config;
    this.fetchImpl =
      opts.fetchImpl ??
      ((url, init) => fetch(url, { method: init.method, signal: init.signal }));
  }

  async review(input: SourceReviewInput): Promise<SourceResult> {
    const startedAt = Date.now();
    const rules = addedLines(input.event.diff);

    const manifests = new Set<string>();
    const dependencies: Dependency[] = [];
    const seen = new Set<string>();
    for (const [file, text] of Object.entries(input.sourceText)) {
      const name = baseName(file);
      const isManifest =
        name === "package.json" || name === "pyproject.toml" || /^requirements.*\.txt$/i.test(name);
      if (!isManifest) continue;
      manifests.add(file);
      const found = collect(text, file);
      for (const dependency of found) {
        const key = `${dependency.ecosystem}\u0000${dependency.name}`;
        if (seen.has(key)) continue;
        if (rules !== null) {
          const added = rules.get(file);
          if (!added || !added.has(dependency.line)) continue;
        }
        seen.add(key);
        dependencies.push(dependency);
      }
    }

    if (dependencies.length === 0) {
      return {
        source: "registry",
        status: "ok",
        findings: [],
        coverage: { filesCovered: manifests.size, filesUnknown: 0 },
        tokens: null,
        latencyMs: Math.max(0, Date.now() - startedAt),
        errorKind: null,
      };
    }

    const findings: Finding[] = [];
    for (const dependency of dependencies) {
      const check = await this.check(dependency);
      if (check.kind === "error") {
        return {
          source: "registry",
          status: "degraded",
          findings: [],
          coverage: { filesCovered: manifests.size, filesUnknown: 0 },
          tokens: null,
          latencyMs: Math.max(0, Date.now() - startedAt),
          errorKind: check.errorKind,
        };
      }
      if (check.kind === "missing") {
        findings.push({
          file: dependency.file,
          startLine: dependency.line,
          endLine: dependency.line,
          severity: 2,
          confidence: 0.9,
          source: "registry",
          cwe: null,
          evidence: `package not found: ${dependency.name}`,
          rawId: `registry\u0000${dependency.name}\u0000${dependency.file}\u0000${dependency.line}`,
        });
      }
    }

    return {
      source: "registry",
      status: "ok",
      findings,
      coverage: { filesCovered: manifests.size, filesUnknown: 0 },
      tokens: null,
      latencyMs: Math.max(0, Date.now() - startedAt),
      errorKind: null,
    };
  }

  private async check(dependency: Dependency): Promise<Check> {
    const url =
      dependency.ecosystem === "npm"
        ? `https://registry.npmjs.org/${encodeURIComponent(dependency.name)}`
        : `https://pypi.org/pypi/${encodeURIComponent(dependency.name)}/json`;
    const method = dependency.ecosystem === "npm" ? "HEAD" : "GET";
    const controller = new AbortController();
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      controller.abort();
    }, this.config.sources.registry.timeoutMs);
    try {
      const response = await this.fetchImpl(url, { method, signal: controller.signal });
      if (response.status === 404) return { kind: "missing" };
      if (response.status >= 200 && response.status < 300) return { kind: "exists" };
      return { kind: "error", errorKind: `status_${response.status}` };
    } catch {
      return { kind: "error", errorKind: timedOut ? "timeout" : "network" };
    } finally {
      clearTimeout(timer);
    }
  }
}

export function createRegistrySource(config: RunConfig, opts: RegistryOptions): RegistrySource {
  return new RegistrySource(config, opts);
}
