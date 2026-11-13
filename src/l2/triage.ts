import type { Tier } from "../contracts/index.js";

export interface TriageInput {
  changedFiles: number;
  impactedFiles: number;
  impactedNodes: number;
  truncated: boolean;
  unresolvedCallSites: number;
  indexReady: boolean;
  indexStale: boolean;
}

export interface TriageResult {
  tier: Tier;
  source: "triage" | "static" | "none";
  degraded: boolean;
  skipReason: "index_not_ready" | "index_stale" | null;
}

export interface TriageBoundaries {
  tier0: { filesMax: number; nodesMax: number };
  tier1: { filesMax: number; nodesMax: number };
}

/**
 * The static ladder: one input, `changedFiles`.
 *
 * Not `risk_level`, not line count, not the defect class — a three-file write is
 * tier 0 whatever it contains, and a one-file write is tier 0 even when it is a
 * whole vulnerable module. `staticTier` is the fallback whenever the graph
 * cannot answer (`index_not_ready`, `index_stale`, or a query that misses
 * `budgets.crgQueryMs`), so on a machine where the graph query is slower than
 * that budget this is the *only* rule in force.
 */
export function staticTier(changedFiles: number, boundaries: TriageBoundaries): Tier {
  if (changedFiles <= boundaries.tier0.filesMax) return 0;
  if (changedFiles <= boundaries.tier1.filesMax) return 1;
  return 2;
}

/**
 * The computed ladder. Inputs: `impactedFiles`, `impactedNodes`, `truncated`
 * and `unresolvedCallSites` — and `changedFiles` only in the degraded branch.
 * `risk_level` appears nowhere; cost is a function of change shape, not of how
 * dangerous the change is judged to be.
 */
export function computeTier(input: TriageInput, boundaries: TriageBoundaries): TriageResult {
  if (!input.indexReady || input.indexStale) {
    return {
      tier: staticTier(input.changedFiles, boundaries),
      source: "static",
      degraded: true,
      skipReason: input.indexReady ? "index_stale" : "index_not_ready",
    };
  }
  let tier: Tier = 2;
  if (input.impactedFiles <= boundaries.tier0.filesMax && input.impactedNodes <= boundaries.tier0.nodesMax) {
    tier = 0;
  } else if (
    input.impactedFiles <= boundaries.tier1.filesMax &&
    input.impactedNodes <= boundaries.tier1.nodesMax
  ) {
    tier = 1;
  }
  if (input.truncated || input.unresolvedCallSites > 0) {
    tier = Math.max(tier, 1) as Tier;
  }
  return { tier, source: "triage", degraded: false, skipReason: null };
}
