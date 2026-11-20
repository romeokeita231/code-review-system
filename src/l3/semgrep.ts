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

import { TOOL_ENV, killProcessTree, sha256 } from "../config/index.js";
import { asNumber, asRecord, asString } from "./json.js";

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
    const child = execa(request.file, request.args, {
      cwd: request.cwd,
      killSignal: "SIGKILL",
      forceKillAfterDelay: 0,
      cleanup: true,
      windowsHide: true,
      reject: false,
      stdin: "ignore",
      env: { ...process.env, ...TOOL_ENV },
    });
    // #49: execa's own timeout kills only the direct child; on Windows the
    // grandchildren keep the stdio pipes open, so `await` never settles. Time
    // it here and kill the tree in one shot, before anything is orphaned.
    let timedOut = false;
    const treeKill = setTimeout(() => {
      timedOut = true;
      killProcessTree(child.pid);
    }, request.timeoutMs);
    try {
      const result = await child;
      return {
        stdout: typeof result.stdout === "string" ? result.stdout : "",
        stderr: typeof result.stderr === "string" ? result.stderr : "",
        exitCode: result.exitCode ?? -1,
        timedOut,
      };
    } finally {
      clearTimeout(treeKill);
    }
  },
};

export interface SemgrepOptions {
  root: string;
  runner?: CommandRunner;
}

const LANGUAGE_BY_EXT: Record<string, string> = {
  ".py": "python",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
};

const DENYLIST_LIMIT = 512;

function toPosix(value: string): string {
  return value.replace(/\\/g, "/");
}

function normalizeRel(value: string): string | null {
  const norm = toPosix(value).replace(/^\.\//, "");
  if (norm.length === 0 || norm.startsWith("/") || /^[A-Za-z]:/.test(norm)) return null;
  if (norm.split("/").some((part) => part === "..")) return null;
  return norm;
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

interface GroupOutcome {
  status: SourceStatus;
  errorKind: string | null;
  covered: number;
  unknown: number;
  findings: Finding[];
}

interface RuleSet {
  id: string;
  sha: string;
  text: string;
  blockRules: string[];
}

export class SemgrepSource implements SignalSource {
  readonly name = "semgrep" as const;

  private readonly config: RunConfig;
  private readonly root: string;
  private readonly runner: CommandRunner;
  private readonly denylist = new Map<string, string>();

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

    const semgrepConfig = this.config.sources.semgrep;
    const small: Materialized[] = [];
    const large: Materialized[] = [];
    let oversized = 0;
    let unsupported = 0;
    for (const item of loaded) {
      const lang = languageOf(item.file);
      const limit = lang === null ? undefined : this.config.sMax[lang];
      const bytes = Buffer.byteLength(item.content, "utf8");
      if (lang === null || limit === undefined) {
        unsupported += 1;
        continue;
      }
      if (bytes > limit) {
        oversized += 1;
        continue;
      }
      if (bytes <= semgrepConfig.fullBlockMaxBytes) small.push(item);
      else large.push(item);
    }

    if (small.length === 0 && large.length === 0) {
      const errorKind = loaded.length > 0 && oversized > 0 ? "file_too_large" : "language_unsupported";
      return blank("degraded", errorKind, startedAt, 0, targets.length);
    }

    const remaining = input.deadline - Date.now();
    const timeoutMs = Math.min(this.config.budgets.semgrepKillMs, remaining);
    if (timeoutMs <= 0) return blank("timeout", "deadline", startedAt, 0, targets.length);

    let tempRoot: string;
    try {
      tempRoot = await mkdtemp(path.join(tmpdir(), "crs-semgrep-"));
    } catch {
      return blank("error", "tempdir", startedAt, 0, targets.length);
    }

    try {
      const written: Materialized[] = [];
      for (const item of [...small, ...large]) {
        const target = path.join(tempRoot, ...item.rel.split("/"));
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, item.content, "utf8");
        written.push(item);
      }

      const outcomes: GroupOutcome[] = [];
      for (const [items, isLarge] of [
        [small, false],
        [large, true],
      ] as const) {
        if (items.length === 0) continue;
        for (const [lang, group] of this.groupByLanguage(items)) {
          outcomes.push(
            await this.scanGroup(lang, isLarge, group, tempRoot, written, timeoutMs),
          );
        }
      }

      const findings: Finding[] = [];
      let covered = 0;
      let unknown = 0;
      const reasons: string[] = [];
      let status: SourceStatus = "ok";
      for (const outcome of outcomes) {
        covered += outcome.covered;
        unknown += outcome.unknown;
        findings.push(...outcome.findings);
        if (outcome.errorKind !== null) reasons.push(outcome.errorKind);
        status = worse(status, outcome.status);
      }
      unknown += oversized + unsupported;
      if (oversized > 0) reasons.push("file_too_large");
      if (unsupported > 0) reasons.push("language_unsupported");

      return blank(
        status,
        reasons.length > 0 ? reasons.join(";") : null,
        startedAt,
        Math.min(covered, targets.length),
        Math.min(unknown, targets.length),
        findings,
      );
    } catch {
      return blank("error", "internal", startedAt, 0, targets.length);
    } finally {
      await rm(tempRoot, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  private groupByLanguage(items: Materialized[]): Map<string, Materialized[]> {
    const groups = new Map<string, Materialized[]>();
    for (const item of items) {
      const lang = languageOf(item.file)!;
      const bucket = groups.get(lang);
      if (bucket) bucket.push(item);
      else groups.set(lang, [item]);
    }
    return groups;
  }

  private async scanGroup(
    lang: string,
    isLarge: boolean,
    items: Materialized[],
    tempRoot: string,
    written: Materialized[],
    timeoutMs: number,
  ): Promise<GroupOutcome> {
    const config = this.config.sources.semgrep;
    const candidates = config.subsets.filter(
      (subset) => subset.langs.includes(lang) && (subset.nontaint === true) === isLarge,
    );
    if (candidates.length === 0) {
      return { status: "degraded", errorKind: "language_unsupported", covered: 0, unknown: items.length, findings: [] };
    }

    const rules: RuleSet[] = [];
    const failures: string[] = [];
    const denyKeys = new Map<string, string>();
    for (const subset of candidates) {
      const absolute = path.isAbsolute(subset.path) ? subset.path : path.resolve(this.root, subset.path);
      try {
        const text = await readFile(absolute, "utf8");
        if (sha256(text) !== subset.sha256) {
          failures.push("rules_sha256");
          continue;
        }
        rules.push({ id: subset.id, sha: subset.sha256, text, blockRules: subset.blockRules });
      } catch {
        failures.push("rules_missing");
        continue;
      }
    }
    if (rules.length === 0) {
      return { status: "degraded", errorKind: failures[0] ?? "rules_missing", covered: 0, unknown: items.length, findings: [] };
    }
    for (const rule of rules) {
      for (const item of items) {
        denyKeys.set(this.denyKey(item, rule.sha), rule.id);
      }
    }

    const allowed = items.filter((item) =>
      rules.every((rule) => !this.denylist.has(this.denyKey(item, rule.sha))),
    );
    if (allowed.length === 0) {
      return { status: "degraded", errorKind: "denylist", covered: 0, unknown: items.length, findings: [] };
    }

    const merged = rules.map((rule) => rule.text).join("\n---\n");
    const ruleFile = path.join(tempRoot, `rules-${lang}-${isLarge ? "nontaint" : "full"}.yaml`);
    await writeFile(ruleFile, merged, "utf8");
    const blockRules = new Set(rules.flatMap((rule) => rule.blockRules));

    const args = [
      "scan",
      "--config",
      ruleFile,
      "--json",
      "--no-git-ignore",
      "--x-semgrepignore-filename",
      ".semgrepignore",
      ...allowed.map((item) => item.rel),
    ];

    const attempt = async (command: string): Promise<{ result: CommandResult | null; engine: "core" | "osemgrep" }> => {
      try {
        return {
          result: await this.runner.run({ file: command, args, cwd: tempRoot, timeoutMs }),
          engine: command === config.command ? "core" : "osemgrep",
        };
      } catch {
        return { result: null, engine: command === config.command ? "core" : "osemgrep" };
      }
    };

    let attemptResult = await attempt(config.command);
    if (attemptResult.result === null || (attemptResult.result.exitCode !== 0 && !attemptResult.result.timedOut)) {
      attemptResult = await attempt(config.osemgrepCommand);
    }
    const result = attemptResult.result;
    if (result === null) {
      return { status: "error", errorKind: "spawn_error", covered: 0, unknown: items.length, findings: [] };
    }
    if (result.timedOut) {
      for (const [key, subsetId] of denyKeys) this.rememberDeny(key, subsetId);
      return { status: "timeout", errorKind: "timeout", covered: 0, unknown: items.length, findings: [] };
    }
    if (result.exitCode !== 0) {
      return { status: "error", errorKind: "exit_code", covered: 0, unknown: items.length, findings: [] };
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(result.stdout);
    } catch {
      return { status: "error", errorKind: "json_parse", covered: 0, unknown: items.length, findings: [] };
    }

    const doc = asRecord(parsed);
    if (doc === null) {
      return { status: "degraded", errorKind: "payload_missing", covered: 0, unknown: items.length, findings: [] };
    }

    const scanned = scannedCount(asRecord(doc["paths"])?.["scanned"]);
    if (scanned !== allowed.length) {
      return { status: "degraded", errorKind: "paths_scanned", covered: 0, unknown: items.length, findings: [] };
    }

    const rawResults = doc["results"];
    const rawErrors = doc["errors"];
    if (!Array.isArray(rawResults) || !Array.isArray(rawErrors)) {
      return { status: "degraded", errorKind: "payload_missing", covered: 0, unknown: items.length, findings: [] };
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

    if (malformed) {
      return { status: "degraded", errorKind: "result_shape", covered: 0, unknown: items.length, findings: [] };
    }
    if (rawResults.length > 0 && !sawEngine) {
      return { status: "degraded", errorKind: "engine_contract", covered: 0, unknown: items.length, findings: [] };
    }

    const findings: Finding[] = [];
    for (const item of coreResults) {
      const file = this.resolveFile(asString(item.result["path"]) ?? "", tempRoot, written);
      if (file === null) {
        return { status: "degraded", errorKind: "path_mismatch", covered: 0, unknown: items.length, findings: [] };
      }
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
        certified: blockRules.has(checkId),
        rawId: `${checkId}\u0000${file}\u0000${startLine}\u0000${endLine}`,
      });
    }

    const unknown = items.length - allowed.length;
    if (rawErrors.length > 0) {
      return { status: "degraded", errorKind: "scan_errors", covered: scanned, unknown, findings };
    }
    if (attemptResult.engine === "osemgrep") {
      return { status: "degraded", errorKind: "engine_osemgrep", covered: scanned, unknown, findings };
    }
    return { status: "ok", errorKind: null, covered: scanned, unknown, findings };
  }

  private denyKey(item: Materialized, subsetSha: string): string {
    return `${item.rel}\u0000${sha256(item.content)}\u0000${subsetSha}`;
  }

  private rememberDeny(key: string, subsetId: string): void {
    if (this.denylist.size >= DENYLIST_LIMIT) {
      const oldest = this.denylist.keys().next().value;
      if (oldest !== undefined) this.denylist.delete(oldest);
    }
    this.denylist.set(key, subsetId);
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

const STATUS_RANK: Record<SourceStatus, number> = { ok: 0, degraded: 1, error: 2, timeout: 3 };

function worse(left: SourceStatus, right: SourceStatus): SourceStatus {
  return STATUS_RANK[right] > STATUS_RANK[left] ? right : left;
}

export function createSemgrepSource(config: RunConfig, opts: SemgrepOptions): SemgrepSource {
  return new SemgrepSource(config, opts);
}
