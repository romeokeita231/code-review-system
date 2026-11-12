import type { ChangeEvent } from "../contracts/index.js";
import { applyEdit, normalizeLf } from "./edit.js";
import {
  commandEvent,
  observePostEvent,
  resolveInRoot,
  synthesizePreEvent,
  toRepoRelative,
} from "./events.js";

export interface HostApi {
  cwd(): string;
  readFile(path: string): Promise<string>;
}

export type HostTrigger = "write" | "edit" | "command";

export interface PreExecuteArgs {
  name: string;
  callId: string;
  rootCallId: string;
  sessionId: string;
  arguments?: unknown;
  ts?: number;
}

export interface PostExecuteArgs extends PreExecuteArgs {
  value?: unknown;
}

export type HookResult =
  | { kind: "allow"; event: ChangeEvent | null }
  | { kind: "deny"; reason: string };

export interface HookAdapter {
  preExecute(args: PreExecuteArgs): Promise<HookResult>;
  postExecute(args: PostExecuteArgs): Promise<ChangeEvent>;
}

export type HostDecision = { decision: "allow" } | { decision: "deny"; reason: string };

export interface PreVerdict {
  decision?: "allow" | "deny" | "not_run";
  preDecision?: "allow" | "deny" | "not_run";
  reason?: string | null;
  text?: string | null;
}

export function triggerFor(name: string): HostTrigger {
  if (name === "write") return "write";
  if (name === "edit") return "edit";
  return "command";
}

function argumentRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {};
}

function stringField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === "string" ? value : null;
}

function valuePair(value: unknown): { before: string | null; after: string } | null {
  if (typeof value !== "object" || value === null) return null;
  const record = value as Record<string, unknown>;
  const after = stringField(record, "after");
  if (after === null) return null;
  return { before: stringField(record, "before"), after };
}

export class DshAdapter implements HookAdapter {
  private readonly roots = new Map<string, string>();

  constructor(
    private readonly api: HostApi & { clock?: () => number },
    private readonly hrtimeId: () => string,
  ) {}

  private now(): number {
    return Math.trunc(this.api.clock?.() ?? Date.now());
  }

  private root(): string {
    const cwd = this.api.cwd();
    const cached = this.roots.get(cwd);
    if (cached !== undefined) return cached;
    const root = cwd.replace(/[\\/]+$/, "") || cwd;
    this.roots.set(cwd, root);
    return root;
  }

  private idOf(args: { callId: string }): string {
    return args.callId.length > 0 ? args.callId : this.hrtimeId();
  }

  private async readOld(filePath: string): Promise<string> {
    try {
      return await this.api.readFile(resolveInRoot(this.root(), filePath));
    } catch {
      return "";
    }
  }

  private relativeOf(filePath: string): string | null {
    try {
      return toRepoRelative(this.root(), filePath);
    } catch {
      return null;
    }
  }

  preDecision(input: ChangeEvent | PreVerdict | null): HostDecision {
    if (input === null) return { decision: "allow" };
    const record = input as unknown as Record<string, unknown>;
    const value = record.decision ?? record.preDecision;
    if (value !== "deny") return { decision: "allow" };
    const reason = record.reason ?? record.text;
    return {
      decision: "deny",
      reason: typeof reason === "string" && reason.length > 0 ? reason : "denied by code review",
    };
  }

  async preExecute(args: PreExecuteArgs): Promise<HookResult> {
    const trigger = triggerFor(args.name);
    if (trigger === "command") return { kind: "allow", event: null };

    const record = argumentRecord(args.arguments);
    const filePath = stringField(record, "file_path");
    if (filePath === null) return { kind: "allow", event: null };

    const path = this.relativeOf(filePath);
    if (path === null) return { kind: "allow", event: null };

    const before = await this.readOld(filePath);
    let after: string;

    if (trigger === "write") {
      const content = stringField(record, "content");
      if (content === null) return { kind: "allow", event: null };
      after = normalizeLf(content);
    } else {
      const oldString = stringField(record, "old_string");
      const newString = stringField(record, "new_string");
      if (oldString === null || newString === null) return { kind: "allow", event: null };
      const applied = applyEdit(before, {
        file_path: filePath,
        old_string: oldString,
        new_string: newString,
        replace_all: record.replace_all === true,
      });
      if ("error" in applied) return { kind: "deny", reason: applied.error };
      after = applied.content;
    }

    const event = synthesizePreEvent({
      id: this.idOf(args),
      sessionId: args.sessionId,
      rootCallId: args.rootCallId,
      trigger,
      files: [{ path, before, after }],
      ts: args.ts ?? this.now(),
    });
    return { kind: "allow", event };
  }

  async postExecute(args: PostExecuteArgs): Promise<ChangeEvent> {
    const base = {
      id: this.idOf(args),
      sessionId: args.sessionId,
      rootCallId: args.rootCallId,
      ts: args.ts ?? this.now(),
    };
    const trigger = triggerFor(args.name);
    if (trigger === "command") return commandEvent(base);

    const record = argumentRecord(args.arguments);
    const filePath = stringField(record, "file_path");
    if (filePath === null) return commandEvent(base);

    const path = this.relativeOf(filePath);
    if (path === null) return commandEvent(base);

    const pair = valuePair(args.value);
    if (pair === null) return commandEvent(base);

    return observePostEvent({ ...base, trigger, path, before: pair.before, after: pair.after });
  }
}
