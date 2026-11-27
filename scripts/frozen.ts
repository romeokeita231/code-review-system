/**
 * The frozen instrument pin.
 *
 * It lives in the preregistration, not in the config, because the config is the
 * thing under test: an edit there must not be able to move the goalposts. The
 * run refuses when the config, the probes or the rows disagree with any value
 * here, and the check is placed before the numbers rather than beside them.
 */
import { readFileSync } from "node:fs";

/** Where the frozen values live. A pin in someone's head is not a pin. */
export const PREREGISTRATION = "artifacts/preregistration.json";

export interface FrozenInstruments {
  semgrep: { version: string };
  /** `ocr` is pinned by build commit, not by release tag. */
  ocr: { commit: string };
  /**
   * The model behind AOR. `id` is the id the service reported (the ruler);
   * `configured` is what the client asked for, which may be an alias.
   */
  aor_model: { provider: string; id: string; url: string | null; configured: string | null };
  /**
   * The graph CLI that decides tier, read from the binary at staging time.
   *
   * It is absent from the preregistration on purpose: a version typed into a
   * config file is a claim, not an observation, and editing it would silently
   * move the tier boundary. Runs staged before this field existed have no
   * `crg`; they stay readable, marked as having an incomplete instrument
   * identity, rather than being re-interpreted with today's binary.
   */
  crg?: { version: string };
}

export function loadFrozenPin(path = PREREGISTRATION): FrozenInstruments {
  const raw = JSON.parse(readFileSync(path, "utf8")) as {
    frozen?: { instruments?: Partial<FrozenInstruments> };
  };
  const instruments = raw.frozen?.instruments;
  const model = instruments?.aor_model;
  if (
    instruments?.semgrep?.version === undefined ||
    instruments.ocr?.commit === undefined ||
    model?.provider === undefined ||
    model.id === undefined
  ) {
    throw new Error(
      `${path} has no frozen.instruments {semgrep.version, ocr.commit, aor_model.{provider,id}}: ` +
        `the pin has to exist before the run it describes`,
    );
  }
  return {
    semgrep: { version: instruments.semgrep.version },
    ocr: { commit: instruments.ocr.commit },
    aor_model: {
      provider: model.provider,
      id: model.id,
      url: model.url ?? null,
      configured: model.configured ?? null,
    },
  };
}

/** The declared token ceiling for AOR spend on one eval run. */
export function loadCostCeiling(path = PREREGISTRATION): number {
  const raw = JSON.parse(readFileSync(path, "utf8")) as {
    frozen?: { cost?: { ceiling_tokens?: unknown } };
  };
  const ceiling = raw.frozen?.cost?.ceiling_tokens;
  if (typeof ceiling !== "number" || !Number.isFinite(ceiling) || ceiling <= 0) {
    throw new Error(
      `${path} has no frozen.cost.ceiling_tokens: a ceiling declared after the fact is not a ceiling`,
    );
  }
  return Math.trunc(ceiling);
}

/**
 * The pre-path budget fixed before the run, with the measurement behind it.
 *
 * `crgQueryMs` is the one value that decides whether the triage layer exists at
 * all: below the graph CLI's floor the query always times out, the tier falls
 * back to the static ladder, and every row becomes tier 0 without anything
 * reporting a failure. So the value is frozen with the latency table that
 * produced it, and the config is compared with it before the run rather than
 * after the numbers exist.
 */
export interface FrozenBudgets {
  crg_query_ms: number;
  /** The floor implied by the warm semgrep latency, not a target value. */
  semgrep_kill_ms: number;
  derivation: string | null;
  semgrep_derivation: string | null;
  /**
   * The distribution behind `semgrep_kill_ms`, when there is one.
   *
   * `null` is the honest reading of the current pin: the floor is
   * `ceil(650 x 1.5)` from a **single** 2026-11-13 observation, which the
   * preregistration itself labels "single observation, not a distribution".
   * One sample cannot separate "warm 650 ms" from "hangs forever", and on this
   * machine semgrep does hang, so the gate has to be able to see the difference
   * between a floor that was measured and a floor that was assumed.
   */
  semgrep_latency: { n: number; p99: number } | null;
}

export function loadFrozenBudgets(path = PREREGISTRATION): FrozenBudgets | null {
  const raw = JSON.parse(readFileSync(path, "utf8")) as {
    frozen?: {
      budgets?: {
        crg_query_ms?: unknown;
        semgrep_kill_ms?: unknown;
        derivation?: unknown;
        semgrep_derivation?: unknown;
        semgrep_latency?: { n?: unknown; p99?: unknown };
      };
    };
  };
  const crg = raw.frozen?.budgets?.crg_query_ms;
  if (typeof crg !== "number" || !Number.isFinite(crg) || crg <= 0) return null;
  const semgrep = raw.frozen?.budgets?.semgrep_kill_ms;
  const derivation = raw.frozen?.budgets?.derivation;
  const semgrepDerivation = raw.frozen?.budgets?.semgrep_derivation;
  const latency = raw.frozen?.budgets?.semgrep_latency;
  const latencyN = typeof latency?.n === "number" ? Math.trunc(latency.n) : null;
  const latencyP99 = typeof latency?.p99 === "number" ? latency.p99 : null;
  return {
    crg_query_ms: Math.trunc(crg),
    semgrep_kill_ms:
      typeof semgrep === "number" && Number.isFinite(semgrep) && semgrep > 0
        ? Math.trunc(semgrep)
        : 0,
    derivation: typeof derivation === "string" ? derivation : null,
    semgrep_derivation: typeof semgrepDerivation === "string" ? semgrepDerivation : null,
    semgrep_latency:
      latencyN === null || latencyP99 === null || latencyN <= 0
        ? null
        : { n: latencyN, p99: latencyP99 },
  };
}
