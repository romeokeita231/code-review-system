import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import type {
  CalibrationArtifact,
  ReviewRow,
  RunConfig,
  SignalSource,
  TriageProvider,
} from "../contracts/index.js";
import { ConfigError, loadCalibration, loadConfig } from "../config/index.js";
import { DshAdapter } from "../l1/index.js";
import { DenyGuard, ConclusionCache, TurnBudgetLedger, ledgerFor, review } from "../l2/index.js";
import { createSources, createTriage } from "../l3/index.js";
import { appendRow } from "../l5/index.js";

/**
 * Cordis plugin identity. DSH's loader resolves the bundle patch row by this
 * name, so it must stay stable.
 */
export const name = "code-review-system";

/** Producer label stamped on every injected correction (`[CRS-WARN]`). */
const SOURCE_KIND = "code-review-system";

/** Bound for the notice summary committed to the durable session log. */
const SUMMARY_MAX_CHARS = 120;

/** Config accepted from the profile patch row. */
export interface PluginConfig {
  /** Path to the RunConfig JSON; absolute, or relative to the process cwd. */
  configPath: string;
  /** Repository root the adapter resolves paths against. Defaults to cwd. */
  root?: string;
  /** Calibration artifact override; defaults to config.calibration.artifactPath. */
  artifactPath?: string;
}

export interface PluginRuntime {
  config: RunConfig;
  artifact: CalibrationArtifact | null;
  sources: SignalSource[];
  triage: TriageProvider | null;
  adapter: DshAdapter;
  ledger: TurnBudgetLedger;
  guards: Map<string, DenyGuard>;
  cache: ConclusionCache;
  jsonlPath: string;
}

/** The subset of `ToolExecution` this adapter reads. */
export interface HookExec {
  name: string;
  callId?: string;
  arguments?: unknown;
  agent?: { session?: { id?: string } };
  rootCallId?: string;
}

/** The subset of `ToolExecutionResult` this adapter reads. */
export interface HookExecResult {
  value?: unknown;
}

export type Decision =
  | { kind: "allow" }
  | { kind: "deny"; reason: string }
  | {
      kind: "accept";
      additionalContexts?: ContextMessage[];
      content?: unknown;
      value?: unknown;
      [key: string]: unknown;
    };

/**
 * One injected user-role message. `source.kind` is the producer's own label:
 * an unlabeled context would render as a human prompt in derived history.
 */
export interface ContextMessage {
  id: string;
  role: "user";
  content: Array<{ type: "text"; text: string }>;
  source: { kind: string; form: "notice"; summary: string };
}

/** Structural view of the Cordis context used for hook registration. */
export interface PluginContext {
  on(event: string, handler: (...args: never[]) => unknown): unknown;
  logger?: {
    warn(...args: unknown[]): void;
    error(...args: unknown[]): void;
  };
}

function normalizeConfig(config: PluginConfig): PluginConfig & { root: string } {
  if (typeof config !== "object" || config === null) {
    throw new ConfigError("code-review-system: missing plugin config");
  }
  if (typeof config.configPath !== "string" || config.configPath.length === 0) {
    throw new ConfigError("code-review-system: configPath is required");
  }
  const configPath = resolve(config.configPath);
  if (!existsSync(configPath)) {
    throw new ConfigError(`code-review-system: config not found: ${configPath}`);
  }
  const artifactPath =
    config.artifactPath === undefined ? undefined : resolve(config.artifactPath);
  if (artifactPath !== undefined && !existsSync(artifactPath)) {
    throw new ConfigError(`code-review-system: calibration artifact not found: ${artifactPath}`);
  }
  return {
    configPath,
    artifactPath,
    root: config.root === undefined ? process.cwd() : resolve(config.root),
  };
}

export async function createRuntime(options: PluginConfig): Promise<PluginRuntime> {
  const config = await loadConfig(options.configPath);
  let artifact: CalibrationArtifact | null = null;
  const artifactPath = options.artifactPath ?? config.calibration.artifactPath;
  try {
    artifact = await loadCalibration(artifactPath);
  } catch {
    artifact = null;
  }
  if (artifact === null && config.fusionStages.calibrate) {
    throw new ConfigError(`calibration artifact is missing: ${config.calibration.artifactPath}`);
  }
  let counter = 0;
  const root = options.root ?? process.cwd();
  return {
    config,
    artifact,
    sources: createSources(config, { root }),
    triage: createTriage(config, { root }),
    adapter: new DshAdapter(
      {
        cwd: () => root,
        readFile: (path: string) => readFile(path, "utf8"),
      },
      () => `crs-${Date.now()}-${(counter += 1)}`,
    ),
    ledger: ledgerFor(config),
    guards: new Map(),
    cache: new ConclusionCache(config.budgets.cacheTtlMs),
    jsonlPath: config.persistence.jsonlPath,
  };
}

function sessionOf(exec: HookExec): string {
  return exec.agent?.session?.id ?? "session";
}

function guardFor(runtime: PluginRuntime, sessionId: string): DenyGuard {
  const existing = runtime.guards.get(sessionId);
  if (existing) return existing;
  const guard = new DenyGuard();
  runtime.guards.set(sessionId, guard);
  return guard;
}

function logError(ctx: PluginContext, message: string, error: unknown): void {
  const text = error instanceof Error ? error.stack ?? error.message : String(error);
  const line = `code-review-system: ${message}: ${text}`;
  if (ctx.logger) ctx.logger.error(line);
  else process.stderr.write(`${line}\n`);
}

function boundSummary(text: string): string {
  const firstLine = text.split("\n")[0] ?? text;
  return firstLine.length <= SUMMARY_MAX_CHARS
    ? firstLine
    : `${firstLine.slice(0, SUMMARY_MAX_CHARS - 1)}…`;
}

/** Build the correction message injected into the next request. */
export function correctionContext(text: string): ContextMessage {
  return {
    id: randomUUID(),
    role: "user",
    content: [{ type: "text", text }],
    source: { kind: SOURCE_KIND, form: "notice", summary: boundSummary(text) },
  };
}

async function reviewPre(runtime: PluginRuntime, exec: HookExec): Promise<Decision> {
  const sessionId = sessionOf(exec);
  const callId = exec.callId ?? `${Date.now()}`;
  const hooked = await runtime.adapter.preExecute({
    name: exec.name,
    callId,
    rootCallId: exec.rootCallId ?? callId,
    sessionId,
    arguments: exec.arguments,
  });
  if (hooked.kind === "deny") return { kind: "deny", reason: hooked.reason };
  if (hooked.event === null) return { kind: "allow" };

  const outcome = await review(hooked.event, {
    runId: callId,
    config: runtime.config,
    sources: runtime.sources,
    triage: runtime.triage,
    artifact: runtime.artifact,
    guard: guardFor(runtime, sessionId),
    ledger: runtime.ledger,
    sourceText: hooked.sourceText,
    cache: runtime.cache,
  });
  await appendRow(runtime.jsonlPath, outcome.row);
  if (outcome.disposition.preDecision === "deny") {
    return { kind: "deny", reason: outcome.disposition.text ?? "blocked by code review" };
  }
  return { kind: "allow" };
}

async function reviewPost(runtime: PluginRuntime, exec: HookExec, result: HookExecResult): Promise<ReviewRow> {
  const sessionId = sessionOf(exec);
  const callId = exec.callId ?? `${Date.now()}`;
  const hooked = await runtime.adapter.postExecute({
    name: exec.name,
    callId,
    rootCallId: exec.rootCallId ?? callId,
    sessionId,
    arguments: exec.arguments,
    value: result?.value,
  });
  const outcome = await review(hooked.event, {
    runId: callId,
    config: runtime.config,
    sources: runtime.sources,
    triage: runtime.triage,
    artifact: runtime.artifact,
    guard: guardFor(runtime, sessionId),
    ledger: runtime.ledger,
    sourceText: hooked.sourceText,
    cache: runtime.cache,
  });
  await appendRow(runtime.jsonlPath, outcome.row);
  return outcome.row;
}

/** Pre-execute body, exported for tests; containment lives in {@link apply}. */
export async function preExecute(runtime: PluginRuntime, exec: HookExec): Promise<Decision> {
  return reviewPre(runtime, exec);
}

/** Post-execute body, exported for tests; containment lives in {@link apply}. */
export async function postExecute(
  runtime: PluginRuntime,
  exec: HookExec,
  result: HookExecResult,
): Promise<{ row: ReviewRow; correction: ContextMessage | null }> {
  const row = await reviewPost(runtime, exec, result);
  const correction =
    row.post_decision === "inject_warn" && row.text ? correctionContext(row.text) : null;
  return { row, correction };
}
/** Attach the correction to whatever the downstream post-decision returned. */
type DownstreamDecision = { kind: string; additionalContexts?: ContextMessage[] };

function mergeContexts<T extends DownstreamDecision>(
  downstream: T,
  message: ContextMessage,
): T & { additionalContexts: ContextMessage[] } {
  const existing = downstream.additionalContexts ?? [];
  return { ...downstream, additionalContexts: [...existing, message] };
}

/**
 * Register the review hooks on a Cordis context.
 *
 * The runtime is loaded eagerly but awaited lazily, so a slow config read never
 * blocks the loader while every hook still sees a fully initialised runtime.
 * Any review failure fails open: an internal fault must never block a write.
 */
export function apply(ctx: PluginContext, config: PluginConfig): void {
  const options = normalizeConfig(config);
  const ready = createRuntime(options);
  ready.catch((error: unknown) => logError(ctx, "initialisation failed", error));

  ctx.on("tools/pre-execute", ((exec: HookExec, next: () => Promise<Decision>) => {
    return (async (): Promise<Decision> => {
      try {
        const runtime = await ready;
        const decision = await preExecute(runtime, exec);
        if (decision.kind === "deny") return decision;
      } catch (error) {
        logError(ctx, "pre-execute review failed open", error);
      }
      return next();
    })();
  }) as never);

  ctx.on("tools/post-execute", ((exec: HookExec, result: HookExecResult, next: () => Promise<Decision>) => {
    return (async (): Promise<Decision> => {
      const downstream = await next();
      try {
        const runtime = await ready;
        const outcome = await postExecute(runtime, exec, result);
        if (outcome.correction === null) return downstream;
        return mergeContexts(downstream, outcome.correction) as Decision;
      } catch (error) {
        logError(ctx, "post-execute review failed open", error);
        return downstream;
      }
    })();
  }) as never);
}

/** Backwards-compatible name for hosts that wire the hooks manually. */
export const register = apply;
