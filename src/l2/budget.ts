import type { RunConfig } from "../contracts/index.js";

export interface Clock {
  now(): number;
}

export const systemClock: Clock = { now: () => Date.now() };

export interface TurnKey {
  sessionId: string;
  rootCallId: string;
}

export class TurnBudgetLedger {
  private readonly spent = new Map<string, number>();

  constructor(
    private readonly budgetMs: number,
    private readonly clock: Clock = systemClock,
  ) {}

  private key(turn: TurnKey): string {
    return `${turn.sessionId}\u0000${turn.rootCallId}`;
  }

  spentMs(turn: TurnKey): number {
    return this.spent.get(this.key(turn)) ?? 0;
  }

  remainingMs(turn: TurnKey): number {
    return Math.max(0, this.budgetMs - this.spentMs(turn));
  }

  canStart(turn: TurnKey, costMs: number): boolean {
    return this.remainingMs(turn) >= costMs;
  }

  charge(turn: TurnKey, elapsedMs: number): void {
    const key = this.key(turn);
    this.spent.set(key, (this.spent.get(key) ?? 0) + Math.max(0, elapsedMs));
  }

  reset(turn: TurnKey): void {
    this.spent.delete(this.key(turn));
  }

  snapshot(): Record<string, number> {
    return Object.fromEntries(this.spent);
  }

  now(): number {
    return this.clock.now();
  }
}

export function ledgerFor(config: RunConfig, clock: Clock = systemClock): TurnBudgetLedger {
  return new TurnBudgetLedger(config.budgets.turnMs, clock);
}

export interface BudgetDecision {
  start: boolean;
  reason: "turn_budget_exhausted" | "budget_exhausted" | null;
  deadline: number;
}

export function planCall(
  ledger: TurnBudgetLedger,
  turn: TurnKey,
  costMs: number,
  capMs: number,
): BudgetDecision {
  const now = ledger.now();
  if (!ledger.canStart(turn, costMs)) {
    return { start: false, reason: "turn_budget_exhausted", deadline: now };
  }
  const remaining = ledger.remainingMs(turn);
  if (remaining < Math.min(costMs, capMs)) {
    return { start: false, reason: "budget_exhausted", deadline: now };
  }
  return { start: true, reason: null, deadline: now + Math.min(costMs, capMs) };
}
