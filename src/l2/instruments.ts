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
import type { Instrument, Instruments, RunConfig } from "../contracts/index.js";
import { TOOL_ENV } from "../config/index.js";

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

/** Ask the binaries that would do the measuring. Cached: one probe per process. */
export function observeInstruments(config: RunConfig, probeFn = probe): Promise<Instruments> {
  if (pending !== null) return pending;
  pending = (async () => {
    const [semgrep, ocr] = await Promise.all([
      probeFn(config.sources.semgrep.command, ["--version"]),
      probeFn(config.sources.aor.command, ["--version"]),
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
    return { semgrep: observed("semgrep", parsedSemgrep), ocr: observed("ocr", parsedOcr) };
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
