/**
 * Measuring-instrument identity.
 *
 * Three times now a measurement quoted a number produced by a tool other than
 * the one named in the config: the `ts_all` probe against a `ts_dedup` load,
 * `semgrep scan` against a `semgrep-core` criterion, and `ocr` self-updating
 * from the pinned `04deca6` to `4236c87` between two sessions. Each time the
 * artefact looked complete. The cause is structural: the row records what the
 * *config* says (`toolchain`), not what answered `--version`.
 *
 * So a measurement artefact carries both. `toolchain` stays as the declaration;
 * `instrument` is what this process observed by asking the binary. Consumers
 * (`assertInstrumentIdentity`) compare the two against a frozen expectation and
 * refuse to emit a number when they disagree - a warning is not enough, because
 * the whole failure mode is a plausible-looking artefact.
 *
 * `ocr` also ships a self-updater: every invocation spawns `scripts/update.js`,
 * which runs `npm i -g` when a newer release exists. That is how the pin was
 * lost once. `TOOL_ENV` turns it off for every process we spawn, so the binary
 * under measurement can only change when a human changes it.
 */
import type { AorModel, Instrument, Instruments, RunConfig } from "../contracts/index.js";
import { TOOL_ENV } from "../config/index.js";
import { readFileSync } from "node:fs";

/** Handed to every tool we spawn; `OCR_NO_UPDATE` is the self-update opt-out. */
export const PROBE_ENV: Record<string, string> = { ...TOOL_ENV };

const DECLARED = "declared";

/**
 * No live tool ran, so the row can only repeat the config. `source: "declared"`
 * marks it ineligible for acceptance evaluation; it is not a weaker measurement,
 * it is not a measurement.
 */
export function declaredInstruments(config: RunConfig): Instruments {
  return {
    semgrep: {
      name: "semgrep",
      version: config.sources.semgrep.version,
      commit: null,
      source: "declared",
    },
    ocr: {
      name: "ocr",
      version: config.sources.aor.versionCommit,
      commit: config.sources.aor.versionCommit,
      source: "declared",
    },
    aor_model: {
      provider: "unrecorded",
      id: "unrecorded",
      params: { url: null, configured: null },
      source: "declared",
    },
  };
}

interface ProbeResult {
  ok: boolean;
  text: string;
}

async function probe(file: string, args: string[]): Promise<ProbeResult> {
  try {
    const { execa } = await import("execa");
    const result = await execa(file, args, {
      env: { ...process.env, ...PROBE_ENV },
      timeout: 60_000,
      reject: false,
      windowsHide: true,
      stdin: "ignore",
    });
    return {
      ok: result.exitCode === 0,
      text: `${result.stdout ?? ""}\n${result.stderr ?? ""}`.trim(),
    };
  } catch (error) {
    return { ok: false, text: (error as Error).message };
  }
}

/**
 * `semgrep --version` prints the bare version (`1.184.0`). Some builds append
 * the commit on a second line, which is worth keeping when it is there.
 */
export function parseSemgrepVersion(text: string): { version: string; commit: string | null } {
  const lines = text
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  const first = lines[0] ?? "";
  const version = first.match(/\d+\.\d+\.\d+[0-9A-Za-z.+-]*/)?.[0] ?? first;
  const commit = text.match(/\b(?:commit|rev)[:=\s]+([0-9a-f]{7,40})\b/i)?.[1] ?? null;
  return { version: version.length > 0 ? version : "unavailable", commit };
}

/**
 * `open-code-review v1.13.6 (04deca6) windows/amd64`
 *
 * The parenthesised token is the build's git commit, and that - not the release
 * tag - is what the config pins. `v1.13.7` was tagged at `b1dcffb`, so a
 * release-number match would silently accept the wrong binary.
 */
export function parseOcrVersion(text: string): { version: string; commit: string | null } {
  const version = text.match(/open-code-review\s+(v?\d+\.\d+\.\d+\S*)/)?.[1];
  const commit = text.match(/\(([0-9a-f]{7,40})\)/)?.[1] ?? null;
  return { version: version ?? (text.split("\n")[0] ?? "unavailable"), commit };
}

let pending: Promise<Instruments> | null = null;

/**
 * `ocr llm test` answers three questions at once: which endpoint, which model
 * serving it, and whether the tool-call round trip works at all. The third is
 * the one that matters - an AOR review is a tool-calling loop, and a model that
 * cannot round-trip a tool call fails every review, not the probe.
 *
 * The printed `Model:` is the service's answer when it sends one
 * (`resp.Model`), not the configured id, so this is the only place the served
 * model is visible.
 */
export interface AorProbe {
  provider: string;
  url: string | null;
  served: string | null;
  roundTrip: boolean;
}

export function parseAorProbe(text: string): AorProbe {
  const provider = text.match(/Source:\s*(?:provider:)?(.+)/)?.[1]?.trim() ?? "unknown";
  const url = text.match(/^URL:\s*(\S+)/m)?.[1] ?? null;
  const served = text.match(/^Model:\s*(\S+)/m)?.[1] ?? null;
  const roundTrip = /tool-call round trip verified/i.test(text) || /Connection test successful/i.test(text);
  return {
    provider: provider.length > 0 ? provider : "unknown",
    url,
    served,
    roundTrip,
  };
}

/**
 * What ocr's own config asks for. This is a *declared* read - the file the
 * client would send - recorded next to the served id so an alias
 * (`deepseek-chat` answered by `deepseek-flash`) is a visible fact rather than
 * an assumption. It never substitutes for the observed id.
 */
export function configuredModelOf(provider: string): string | null {
  try {
    const home = process.env["USERPROFILE"] ?? process.env["HOME"] ?? "";
    if (home.length === 0) return null;
    const path = `${home}\\.opencodereview\\config.json`;
    const parsed = JSON.parse(readFileSync(path, "utf8")) as {
      providers?: Record<string, { model?: unknown }>;
    };
    const model = parsed.providers?.[provider]?.model;
    return typeof model === "string" && model.length > 0 ? model : null;
  } catch {
    return null;
  }
}

/**
 * Ask the binaries that would do the measuring. Cached: one probe per process.
 *
 * The AOR probe is a real request (`ocr llm test`), not a config read: the gate
 * is "can it answer", not "is it configured". Its cost is a few thousand
 * tokens once per process, which buys the served model id and a tool-call
 * round trip that no local file can report.
 */
export function observeInstruments(config: RunConfig, probeFn = probe): Promise<Instruments> {
  if (pending !== null) return pending;
  pending = (async () => {
    const [semgrep, ocr, aor] = await Promise.all([
      probeFn(config.sources.semgrep.command, ["--version"]),
      probeFn(config.sources.aor.command, ["--version"]),
      probeFn(config.sources.aor.command, ["llm", "test"]),
    ]);
    const parsedSemgrep = semgrep.ok
      ? parseSemgrepVersion(semgrep.text)
      : { version: "unavailable", commit: null };
    const parsedOcr = ocr.ok ? parseOcrVersion(ocr.text) : { version: "unavailable", commit: null };
    const observed = (name: string, value: { version: string; commit: string | null }): Instrument => ({
      name,
      version: value.version,
      commit: value.commit,
      source: "observed",
    });
    const aorProbe = parseAorProbe(aor.text);
    // A probe that did not answer leaves the model `unavailable`, which the
    // acceptance check refuses. That is the point: a row with no record of the
    // model that wrote it is not a measurement.
    const aorModel: AorModel = {
      provider: aor.ok && aorProbe.provider.length > 0 ? aorProbe.provider : "unavailable",
      id: aor.ok && aorProbe.served !== null ? aorProbe.served : "unavailable",
      params: {
        url: aorProbe.url,
        configured: aor.ok ? configuredModelOf(aorProbe.provider) : null,
      },
      source: "observed",
    };
    return { semgrep: observed("semgrep", parsedSemgrep), ocr: observed("ocr", parsedOcr), aor_model: aorModel };
  })();
  return pending;
}

/** Tests need a clean cache; production never calls this. */
export function resetInstrumentCache(): void {
  pending = null;
}

/**
 * Live runs observe; replay runs declare. Replay never spawns a tool, so it has
 * nothing to observe and says so instead of borrowing the config's authority.
 */
export function instrumentFor(config: RunConfig, observe = observeInstruments): Promise<Instruments> {
  return config.mode === "live"
    ? observe(config)
    : Promise.resolve(declaredInstruments(config));
}
