import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type {
  Finding,
  RunConfig,
  SignalSource,
  SourceResult,
  SourceReviewInput,
  SourceStatus,
} from "../contracts/index.js";

export interface CommandRequest {
  file: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
}

export interface CommandRunner {
  run(request: CommandRequest): Promise<CommandResult>;
}

export const execaRunner: CommandRunner = {
  async run(request: CommandRequest): Promise<CommandResult> {
    const { execa } = await import("execa");
    const result = await execa(request.file, request.args, {
      cwd: request.cwd,
      timeout: request.timeoutMs,
      killSignal: "SIGKILL",
      forceKillAfterDelay: 0,
      cleanup: true,
      windowsHide: true,
      reject: false,
      stdin: "ignore",
    });
    return {
      stdout: typeof result.stdout === "string" ? result.stdout : "",
      stderr: typeof result.stderr === "string" ? result.stderr : "",
      exitCode: result.exitCode ?? -1,
      timedOut: result.timedOut ?? false,
    };
  },
};

export interface SemgrepOptions {
  root: string;
  runner?: CommandRunner;
}

const DEFAULT_MAX_BYTES = 100 * 1024;

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".py": "py",
  ".ts": "ts",
  ".tsx": "ts",
  ".js": "js",
  ".jsx": "js",
  ".mjs": "js",
  ".cjs": "js",
};

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function normalizeRel(value: string): string | null {
  const norm = toPosix(value).replace(/^\.\//, "");
  if (norm.length === 0 || norm.startsWith("/") || /^[A-Za-z]:/.test(norm)) return null;
  if (norm.split("/").some((part) => part === "..")) return null;
  return norm;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
  return typeof value === "string" ? value : null;
}

function asNumber(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function languageOf(file: string): string | null {
  return LANGUAGE_BY_EXT[path.extname(file).toLowerCase()] ?? null;
}

function severityNumber(value: string | null): number {
  switch ((value ?? "").toUpperCase()) {
    case "ERROR":
      return 3;
    case "WARNING":
      return 2;
    case "INFO":
      return 1;
    default:
      return 2;
  }
}

function confidenceNumber(value: string | null): number {
  switch ((value ?? "").toUpperCase()) {
    case "HIGH":
      return 0.9;
    case "MEDIUM":
      return 0.6;
    case "LOW":
      return 0.3;
    default:
      return 0.5;
  }
}

function normalizeCwe(value: unknown): string | null {
  const raw = Array.isArray(value)
    ? (value.find((item) => typeof item === "string") ?? null)
    : value;
  if (typeof raw !== "string") return null;
  const match = /^CWE-\d+/.exec(raw.trim());
  return match ? match[0] : null;
}

function evidenceOf(extra: Record<string, unknown>): string | null {
  const lines = asString(extra["lines"]);
  if (!lines) return null;
  const first = (lines.trim().split("\n")[0] ?? "").trim();
  return first.length > 0 ? first.slice(0, 200) : null;
}

function engineOf(extra: Record<string, unknown>): string | null {
  const engine = asString(extra["engine"]);
  if (engine !== null) return engine;
  const kind = asString(extra["engine_kind"]);
  if (kind === null) return null;
  return kind.toUpperCase() === "OSS" ? "core" : kind.toLowerCase();
}

function scannedCount(value: unknown): number | null {
  if (Array.isArray(value)) return value.length;
  return asNumber(value);
}

function blank(
  status: SourceStatus,
  errorKind: string | null,
  startedAt: number,
  filesCovered: number,
  filesUnknown: number,
  findings: Finding[] = [],
): SourceResult {
  return {
    source: "semgrep",
    status,
    findings,
    coverage: { filesCovered, filesUnknown },
    tokens: null,
    latencyMs: Math.max(0, Date.now() - startedAt),
    errorKind,
  };
}

interface Materialized {
  file: string;
  rel: string;
  content: string;
}

export class SemgrepSource implements SignalSource {
  readonly name = "semgrep" as const;

  private readonly config: RunConfig;
  private readonly root: string;
  private readonly runner: CommandRunner;

  constructor(config: RunConfig, opts: SemgrepOptions) {
    this.config = config;
    this.root = opts.root;
    this.runner = opts.runner ?? execaRunner;
  }

  async review(input: SourceReviewInput): Promise<SourceResult> {
    const startedAt = Date.now();
    const targets = [...new Set(input.event.files ?? [])];
    if (targets.length === 0) return blank("ok", null, startedAt, 0, 0);

    const loaded: Materialized[] = [];
    for (const target of targets) {
      const rel = normalizeRel(target);
      if (rel === null) return blank("error", "input_path", startedAt, 0, targets.length);
      let content = input.sourceText[target] ?? input.sourceText[rel];
      if (content === undefined) {
        try {
          content = await readFile(path.join(this.root, rel), "utf8");
        } catch {
          return blank("error", "input_read", startedAt, 0, targets.length);
        }
      }
      loaded.push({ file: target, rel, content });
    }

    const limits = this.config.sources.semgrep.failOpenOverBytes;
    for (const item of loaded) {
      const lang = languageOf(item.file);
      const limit = (lang !== null ? limits[lang] : undefined) ?? DEFAULT_MAX_BYTES;
      if (Buffer.byteLength(item.content, "utf8") > limit) {
        return blank("degraded", "file_too_large", startedAt, 0, targets.length);
      }
    }

    const remaining = input.deadline - Date.now();
    const timeoutMs = Math.min(this.config.sources.semgrep.timeoutsMs.callMs, remaining);
    if (timeoutMs <= 0) return blank("timeout", "deadline", startedAt, 0, targets.length);

    let tempRoot: string;
    try {
      tempRoot = await mkdtemp(path.join(tmpdir(), "crs-semgrep-"));
    } catch {
      return blank("error", "tempdir", startedAt, 0, targets.length);
    }

    try {
      for (const item of loaded) {
        const target = path.join(tempRoot, ...item.rel.split("/"));
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, item.content, "utf8");
      }

      let result: CommandResult;
      try {
        result = await this.runner.run({
          file: this.config.sources.semgrep.command,
          args: [
            "scan",
            "--config",
            this.config.sources.semgrep.rulesPath,
            "--json",
            "--no-git-ignore",
            "--x-semgrepignore-filename",
            ".semgrepignore",
            ...loaded.map((item) => item.rel),
          ],
          cwd: tempRoot,
          timeoutMs,
        });
      } catch {
        return blank("error", "spawn_error", startedAt, 0, targets.length);
      }

      if (result.timedOut) return blank("timeout", "timeout", startedAt, 0, targets.length);
      if (result.exitCode !== 0) return blank("error", "exit_code", startedAt, 0, targets.length);

      let parsed: unknown;
      try {
        parsed = JSON.parse(result.stdout);
      } catch {
        return blank("error", "json_parse", startedAt, 0, targets.length);
      }

      const doc = asRecord(parsed);
      if (doc === null) return blank("degraded", "payload_missing", startedAt, 0, targets.length);

      const paths = asRecord(doc["paths"]);
      const scanned = scannedCount(paths?.["scanned"]);
      if (scanned !== 1) {
        return blank("degraded", "paths_scanned", startedAt, 0, targets.length);
      }

      const rawResults = doc["results"];
      const rawErrors = doc["errors"];
      if (!Array.isArray(rawResults) || !Array.isArray(rawErrors)) {
        return blank("degraded", "payload_missing", startedAt, 0, targets.length);
      }

      const coreResults: Array<{ result: Record<string, unknown>; extra: Record<string, unknown> }> = [];
      let sawEngine = false;
      let malformed = false;
      for (const raw of rawResults) {
        const result = asRecord(raw);
        if (result === null) {
          malformed = true;
          break;
        }
        if (asString(result["check_id"]) === null || asString(result["path"]) === null) {
          malformed = true;
          break;
        }
        const start = asRecord(result["start"]);
        const end = asRecord(result["end"]);
        if (asNumber(start?.["line"]) === null || asNumber(end?.["line"]) === null) {
          malformed = true;
          break;
        }
        const extra = asRecord(result["extra"]);
        if (extra === null) {
          malformed = true;
          break;
        }
        const engine = engineOf(extra);
        if (engine !== null) sawEngine = true;
        if (engine === "core") coreResults.push({ result, extra });
      }

      if (malformed) return blank("degraded", "result_shape", startedAt, 0, targets.length);
      if (rawResults.length > 0 && !sawEngine) {
        return blank("degraded", "engine_contract", startedAt, 0, targets.length);
      }

      const findings: Finding[] = [];
      for (const item of coreResults) {
        const file = this.resolveFile(asString(item.result["path"]) ?? "", tempRoot, loaded);
        if (file === null) return blank("degraded", "path_mismatch", startedAt, 0, targets.length);
        const checkId = asString(item.result["check_id"])!;
        const startLine = asNumber(asRecord(item.result["start"])?.["line"])!;
        const endLine = asNumber(asRecord(item.result["end"])?.["line"])!;
        const metadata = asRecord(item.extra["metadata"]);
        const severity = severityNumber(
          asString(metadata?.["severity"]) ?? asString(item.extra["severity"]),
        );
        const confidence = confidenceNumber(asString(metadata?.["confidence"]));
        findings.push({
          file,
          startLine,
          endLine,
          severity,
          confidence,
          source: "semgrep",
          cwe: normalizeCwe(metadata?.["cwe"]),
          evidence: evidenceOf(item.extra),
          rawId: `${checkId}\u0000${file}\u0000${startLine}\u0000${endLine}`,
        });
      }

      const filesUnknown = Math.max(0, targets.length - scanned);
      if (rawErrors.length > 0) {
        return blank("degraded", "scan_errors", startedAt, scanned, filesUnknown, findings);
      }
      return blank("ok", null, startedAt, scanned, filesUnknown, findings);
    } catch {
      return blank("error", "internal", startedAt, 0, targets.length);
    } finally {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  private resolveFile(rawPath: string, tempRoot: string, loaded: Materialized[]): string | null {
    const norm = toPosix(rawPath);
    if (norm.length === 0) return null;
    const prefix = `${toPosix(tempRoot)}/`;
    const relative = norm.startsWith(prefix) ? norm.slice(prefix.length) : norm;
    const hit = loaded.find((item) => item.rel === relative);
    if (hit) return hit.file;
    if (path.isAbsolute(rawPath) || /^[A-Za-z]:/.test(rawPath)) return null;
    return relative;
  }
}

export function createSemgrepSource(config: RunConfig, opts: SemgrepOptions): SemgrepSource {
  return new SemgrepSource(config, opts);
}
