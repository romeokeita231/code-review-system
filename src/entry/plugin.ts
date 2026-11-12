import { appendFile, mkdir, readFile } from "node:fs/promises";
import { dirname } from "node:path";
import type { CalibrationArtifact, ReviewRow, RunConfig, SignalSource } from "../contracts/index.js";
import { loadCalibration, loadConfig } from "../config/index.js";
import { DshAdapter } from "../l1/index.js";
import { DenyGuard, TurnBudgetLedger, ledgerFor, review, type TriageProvider } from "../l2/index.js";
import { createSources, createTriage } from "../l3/index.js";

export interface PluginOptions {
  configPath: string;
  root: string;
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
  jsonlPath: string;
}

export interface HookExec {
  name: string;
  callId?: string;
  arguments?: unknown;
  agent?: { session?: { id?: string } };
  rootCallId?: string;
}

export interface HookExecResult {
  value?: unknown;
}

type Decision =
  | { kind: "allow" }
  | { kind: "deny"; reason: string }
  | { kind: "accept"; additionalContexts?: Array<{ role: "user"; content: Array<{ type: "text"; text: string }> }> };

export async function createRuntime(options: PluginOptions): Promise<PluginRuntime> {
  const config = await loadConfig(options.configPath);
  let artifact: CalibrationArtifact | null = null;
  try {
    artifact = await loadCalibration(options.artifactPath ?? config.calibration.artifactPath);
  } catch {
    artifact = null;
  }
  let counter = 0;
  return {
    config,
    artifact,
    sources: createSources(config, { root: options.root }),
    triage: createTriage(config, { root: options.root }),
    adapter: new DshAdapter({
      cwd: () => options.root,
      readFile: (path: string) => readFile(path, "utf8"),
    }, () => `crs-${Date.now()}-${(counter += 1)}`),
    ledger: ledgerFor(config),
    guards: new Map(),
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

async function persist(runtime: PluginRuntime, row: ReviewRow): Promise<void> {
  await mkdir(dirname(runtime.jsonlPath), { recursive: true });
  await appendFile(runtime.jsonlPath, `${JSON.stringify(row)}\n`, "utf8");
}

export async function preExecute(runtime: PluginRuntime, exec: HookExec): Promise<Decision> {
  const sessionId = sessionOf(exec);
  const callId = exec.callId ?? `${Date.now()}`;
  const args = {
    name: exec.name,
    callId,
    rootCallId: exec.rootCallId ?? callId,
    sessionId,
    arguments: exec.arguments,
  };
  const hooked = await runtime.adapter.preExecute(args);
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
  });
  await persist(runtime, outcome.row);
  if (outcome.disposition.preDecision === "deny") {
    return { kind: "deny", reason: outcome.disposition.text ?? "blocked by code review" };
  }
  return { kind: "allow" };
}

export async function postExecute(
  runtime: PluginRuntime,
  exec: HookExec,
  result: HookExecResult,
): Promise<Decision> {
  const sessionId = sessionOf(exec);
  const callId = exec.callId ?? `${Date.now()}`;
  const event = await runtime.adapter.postExecute({
    name: exec.name,
    callId,
    rootCallId: exec.rootCallId ?? callId,
    sessionId,
    arguments: exec.arguments,
    value: result.value,
  });
  if (event.files === null) return { kind: "accept" };

  const outcome = await review(event, {
    runId: callId,
    config: runtime.config,
    sources: runtime.sources,
    triage: runtime.triage,
    artifact: runtime.artifact,
    guard: guardFor(runtime, sessionId),
    ledger: runtime.ledger,
  });
  await persist(runtime, outcome.row);
  if (outcome.disposition.postDecision === "inject_warn" && outcome.disposition.text) {
    return {
      kind: "accept",
      additionalContexts: [
        { role: "user", content: [{ type: "text", text: outcome.disposition.text }] },
      ],
    };
  }
  return { kind: "accept" };
}

export function register(ctx: { on(name: string, handler: (...args: never[]) => unknown): void }, runtime: PluginRuntime): void {
  ctx.on("tools/pre-execute", ((exec: HookExec, next: () => Promise<Decision>) =>
    preExecute(runtime, exec).then((decision) => (decision.kind === "deny" ? decision : next()))) as never);
  ctx.on("tools/post-execute", ((exec: HookExec, result: HookExecResult, next: () => Promise<Decision>) =>
    postExecute(runtime, exec, result).then((decision) => (decision.kind === "accept" ? decision : next()))) as never);
}
