import { createHash } from "node:crypto";
import type { SourceResult } from "../contracts/index.js";
import { systemClock, type Clock } from "./budget.js";

interface Entry {
  at: number;
  result: SourceResult;
}

export class ConclusionCache {
  private readonly entries = new Map<string, Entry>();

  constructor(
    private readonly ttlMs: number,
    private readonly clock: Clock = systemClock,
  ) {}

  key(
    source: string,
    files: readonly string[],
    sourceText: Record<string, string>,
    tier: number,
  ): string {
    const parts = [...files].sort().map((file) => {
      const content = sourceText[file] ?? "";
      return `${file}\u0000${createHash("sha256").update(content).digest("hex")}`;
    });
    return `${source}\u0000${tier}\u0000${parts.join("\u0001")}`;
  }

  get(key: string): SourceResult | null {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (this.clock.now() - entry.at > this.ttlMs) {
      this.entries.delete(key);
      return null;
    }
    return entry.result;
  }

  set(key: string, result: SourceResult): void {
    this.entries.set(key, { at: this.clock.now(), result });
  }
}
