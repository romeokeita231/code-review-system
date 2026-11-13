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
