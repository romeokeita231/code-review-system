import type { ChangeEvent } from "../contracts/index.js";
import { normalizeLf } from "./edit.js";

export interface EventBase {
  id: string;
  sessionId: string;
  rootCallId: string;
  ts: number;
}

export interface FileChange {
  path: string;
  before: string | null;
  after: string;
}

export interface PreEventInput extends EventBase {
  trigger: "write" | "edit";
  files: FileChange[];
}

export interface PostEventInput extends EventBase {
  trigger: "write" | "edit";
  path: string;
  before: string | null;
  after: string;
}

export type CommandEventInput = EventBase;

interface PathTokens {
  prefix: string;
  parts: string[];
}

function isAbsolutePath(input: string): boolean {
  return /^[A-Za-z]:/.test(input) || /^[\\/]/.test(input);
}

export function resolveInRoot(root: string, path: string): string {
  if (isAbsolutePath(path)) return path;
  return `${root.replace(/[\\/]+$/, "")}/${path}`;
}

function tokenize(input: string): PathTokens {
  const unix = input.replace(/\\/g, "/");
  let prefix = "";
  let rest = unix;

  if (/^[A-Za-z]:/.test(unix)) {
    prefix = unix.slice(0, 2).toLowerCase();
    rest = unix.slice(2);
  } else if (unix.startsWith("//")) {
    const body = unix.slice(2);
    const slash = body.indexOf("/");
    const host = slash === -1 ? body : body.slice(0, slash);
    prefix = `//${host.toLowerCase()}`;
    rest = slash === -1 ? "" : body.slice(slash);
  }

  const parts: string[] = [];
  for (const segment of rest.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") {
      parts.pop();
      continue;
    }
    parts.push(segment);
  }

  return { prefix, parts };
}

export function toRepoRelative(root: string, absPath: string): string {
  const rootTokens = tokenize(root);
  const targetTokens = tokenize(resolveInRoot(root, absPath));
  const caseInsensitive = targetTokens.prefix !== "";
  const equal = (left: string, right: string): boolean =>
    caseInsensitive ? left.toLowerCase() === right.toLowerCase() : left === right;

  if (!equal(rootTokens.prefix, targetTokens.prefix)) {
    throw new Error(`path outside repo root: ${absPath}`);
  }
  if (targetTokens.parts.length <= rootTokens.parts.length) {
    throw new Error(`path outside repo root: ${absPath}`);
  }
  for (let index = 0; index < rootTokens.parts.length; index += 1) {
    if (!equal(rootTokens.parts[index]!, targetTokens.parts[index]!)) {
      throw new Error(`path outside repo root: ${absPath}`);
    }
  }

  return targetTokens.parts.slice(rootTokens.parts.length).join("/");
}

function splitLines(text: string | null): string[] {
  if (text === null) return [];
  const normalized = normalizeLf(text);
  if (normalized.length === 0) return [];
  const lines = normalized.split("\n");
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

export function synthesizeDiff(path: string, before: string | null, after: string): string {
  const oldLines = splitLines(before);
  const newLines = splitLines(normalizeLf(after));
  const lines: string[] = [`--- a/${path}`, `+++ b/${path}`];
  const max = Math.max(oldLines.length, newLines.length);

  for (let index = 0; index < max; index += 1) {
    const oldLine = oldLines[index];
    const newLine = newLines[index];
    if (oldLine === newLine) continue;
    if (oldLine !== undefined) lines.push(`-${oldLine}`);
    if (newLine !== undefined) lines.push(`+${newLine}`);
  }

  return lines.join("\n");
}

export function synthesizePreEvent(input: PreEventInput): ChangeEvent {
  return {
    id: input.id,
    sessionId: input.sessionId,
    rootCallId: input.rootCallId,
    phase: "pre",
    trigger: input.trigger,
    files: input.files.map((file) => file.path),
    diff: input.files.map((file) => synthesizeDiff(file.path, file.before, file.after)).join("\n"),
    diffProvenance: "synthesized",
    ts: input.ts,
  };
}

export function observePostEvent(input: PostEventInput): ChangeEvent {
  return {
    id: input.id,
    sessionId: input.sessionId,
    rootCallId: input.rootCallId,
    phase: "post",
    trigger: input.trigger,
    files: [input.path],
    diff: synthesizeDiff(input.path, input.before, input.after),
    diffProvenance: "observed",
    ts: input.ts,
  };
}

export function commandEvent(input: CommandEventInput): ChangeEvent {
  return {
    id: input.id,
    sessionId: input.sessionId,
    rootCallId: input.rootCallId,
    phase: "post",
    trigger: "command",
    files: null,
    diff: null,
    diffProvenance: "none",
    ts: input.ts,
  };
}

export function noChange(before: string | null, after: string): boolean {
  if (before === null) return false;
  return normalizeLf(before) === normalizeLf(after);
}
