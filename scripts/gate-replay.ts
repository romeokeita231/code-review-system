/**
 * Replay the incidents through the checks.
 *
 * This is the delivery criterion, made executable. The retro's rule was: *replay
 * the incident, and the new check has to go red first*. "Go red first" is
 * usually a thing a person does once, in a terminal, before writing a paragraph
 * about it. A paragraph cannot fail. This can: every fixture below is the
 * incident's own inputs, fed to the check that is supposed to catch it, with the
 * expected state written down. If a later edit weakens a check, the fixture goes
 * green where it must be red and `npm run gate:replay` exits 1.
 *
 * The fixtures are data, not prose: each one cites where its numbers come from,
 * so it can be re-derived instead of trusted.
 *
 * Two fixtures exist per friction where possible - the incident, and a **control**
 * that must stay green. A check that fires on everything is not a check; it is
 * noise that gets disabled, which is how the original gap reopened.
 */
import { loadFrozenBudgets } from "./frozen.js";
import {
  judgeMachine,
  judgeSemgrepAnswer,
  judgeSemgrepFloor,
  nearestRankP,
  type Budgets,
  type ImpactMeasurement,
} from "./instrument-gate.js";
import { judgeGateEntrypoints, judgePairGrouping, judgeTruncatedRun, judgeRowsSource, judgeDefectSpans } from "./silent-degeneration.js";
import { judgeHashAgreement, type ResolvedRecord } from "./hash-agreement.js";
import { contentSha256, sha256 } from "../src/config/index.js";
import type { GateVerdict } from "./shared.js";
import { classifyResidue, DEFAULT_LIMITS, judgePatrolCoverage, type ProcessEntry } from "./residue-check.js";
import { judgeRunRepo, REPO_RECORDING_SINCE } from "./repo-identity.js";

type State = "red" | "na" | "green";

interface Replay {
  /** What went wrong, in the words the record uses. */
  incident: string;
  /** Where the inputs come from, so the fixture is re-derivable. */
  source: string;
  /** The row to judge, by name. */
  row: string;
  expect: State;
  /** A single check, or the several a gate returns together. */
  verdicts: readonly GateVerdict[] | GateVerdict;
}

const BUDGETS: Budgets = { crgQueryMs: 993, semgrepKillMs: 5000, callMs: 8000 };
const FROZEN_FLOOR = { crg_query_ms: 993 };

/** Rule text in its CRLF form, which is what this machine's checkout holds. */
const CRLF_RULES = "rules:\n  - id: command-injection-os-system\n    severity: ERROR\n".replace(/\n/g, "\r\n");

/**
 * `sha256` of that text with its line endings folded - so this pin holds for the
 * CRLF form and the LF form both. Re-derive with `contentSha256`; a literal is
 * the point, because a pin in the repository is also a literal.
 */
const CRLF_RULES_CONTENT_SHA = "d67d33134d1c56b6335e92b8a6e59087abbd0c9a0d7106ffdcdd1465c15268f2";

/** A measurement of this shape, with the pooled p99 the record gives. */
function measurement(p99: number, n: number, buildMs: number | null): ImpactMeasurement {
  const samples = Array.from({ length: n }, (_, index) =>
    // A distribution whose nearest-rank p99 is exactly `p99`: all but the top
    // sample sit at 60% of it.
    index === n - 1 ? p99 : Math.round(p99 * 0.6),
  );
  return {
    workload: "fixture",
    files: 10,
    buildMs,
    version: "2.3.9",
    stdio: "file",
    n,
    answered: n,
    p50: nearestRankP(samples, 0.5),
    p99: nearestRankP(samples, 0.99),
    samples,
  };
}

function stateOf(
  verdicts: readonly GateVerdict[] | GateVerdict,
  row: string,
): { state: State; detail: string } {
  const list = Array.isArray(verdicts) ? verdicts : [verdicts as GateVerdict];
  const verdict = list.find((candidate) => candidate.name === row);
  if (verdict === undefined) return { state: "na", detail: `no verdict named "${row}"` };
  const state: State = verdict.na === true ? "na" : verdict.ok ? "green" : "red";
  return { state, detail: verdict.detail };
}

function replays(): Replay[] {
  const frozen = loadFrozenBudgets();
  if (frozen === null) throw new Error("artifacts/preregistration.json has no frozen.budgets");
  const stale = (entries: ProcessEntry[]): readonly GateVerdict[] =>
    classifyResidue(entries, DEFAULT_LIMITS);

  return [
    // ① environment drift -----------------------------------------------------
    {
      incident: "① 2026-11-19: same commits, pooled p99 2364 ms against an archived 662",
      source: "docs/live-drill.md, 'Re-measurement attempt, 2026-11-19' table + preregistration frozen.budgets",
      row: "frozen floor describes this machine",
      expect: "red",
      verdicts: judgeMachine(measurement(2364, 44, 48182), FROZEN_FLOOR, BUDGETS),
    },
    {
      incident: "① 2026-11-20: pooled p99 2672 ms; ceil(1.5 x 2672) = 4008 no longer fits callMs 8000",
      source: "docs/live-drill.md, 'Re-measurement, 2026-11-20' table",
      row: "pre path fits the call budget",
      expect: "red",
      verdicts: judgeMachine(measurement(2672, 44, 50377), FROZEN_FLOOR, BUDGETS),
    },
    {
      incident: "① a config still at the frozen 993 ms runs on this machine and kills every impact",
      source: "docs/live-drill.md: 'A config at the frozen 993 ms would kill every impact call on this machine'",
      row: "configured budget covers this machine",
      expect: "red",
      verdicts: judgeMachine(measurement(2672, 44, 50377), FROZEN_FLOOR, BUDGETS),
    },
    {
      incident: "① control: the archived measurement itself must stay green, or the gate is noise",
      source: "artifacts/preregistration.json frozen.budgets.latency.pooled: n=44, p99 662",
      row: "frozen floor describes this machine",
      expect: "green",
      verdicts: judgeMachine(measurement(662, 44, 1510), FROZEN_FLOOR, BUDGETS),
    },

    // ② residue ---------------------------------------------------------------
    {
      incident:
        "② a `pysemgrep --version` from 15:38 burned 5 h of CPU and nothing looked for it",
      source: "docs/live-drill.md, 2026-11-20 suspect table, first row",
      row: "no leftover instrument process",
      expect: "red",
      verdicts: stale([
        { name: "python.exe", pid: 4242, cpuMs: 5 * 3_600_000, ageMs: 5 * 3_600_000 },
      ]),
    },
    {
      incident: "② control: a scan that is legitimately running right now must not be reported",
      source: "the patrol runs before staging and after the run; a live child is the normal case",
      row: "no leftover instrument process",
      expect: "green",
      verdicts: stale([{ name: "semgrep.exe", pid: 99, cpuMs: 1_200, ageMs: 2_000 }]),
    },
    {
      incident: "② an idle long-lived process is not residue either - CPU has to clear the limit too",
      source: "rule: old AND expensive, so a quiet daemon does not page anyone",
      row: "no leftover instrument process",
      expect: "green",
      verdicts: stale([{ name: "python.exe", pid: 7, cpuMs: 3_000, ageMs: 9 * 3_600_000 }]),
    },

    // ③ the replacement check does not start ---------------------------------
    {
      incident: "③ `wiring:check` exits 1 with `spawn EPERM` from esbuild in the default sandbox",
      source: "npm run wiring:check, this machine, 2026-11-27: errno -4048, syscall 'spawn', startSyncServiceWorker",
      row: "gate entrypoints start without a transpiler",
      expect: "red",
      verdicts: judgeGateEntrypoints({
        "wiring:check": "tsx scripts/wiring-check.ts",
        "gate:machine": "node scripts/run.mjs instrument-gate",
      }),
    },
    {
      incident:
        "③b a patrol that cannot enumerate the process table reports a clean machine",
      source:
        "piped stdio is spawn EPERM here, so any check that shells out must fail loudly when it cannot look",
      row: "residue patrol looked",
      expect: "red",
      verdicts: judgePatrolCoverage(null),
    },
    {
      incident: "③b control: an enumeration that actually returned processes passes",
      source: "29 processes enumerated on this machine, 0 watched",
      row: "residue patrol looked",
      expect: "green",
      verdicts: judgePatrolCoverage([{ name: "explorer.exe", pid: 1, cpuMs: 0, ageMs: 1_000 }]),
    },

    // ④ a source degrades silently -------------------------------------------
    {
      incident: "④ semgrep does not answer: 180 s single-file scan, and `--version` hangs the same way",
      source: "docs/live-drill.md, 2026-11-20 section, final paragraph",
      row: "semgrep answers inside its budget",
      expect: "red",
      verdicts: [
        judgeSemgrepAnswer({
          kind: "timeout",
          elapsedMs: 180_000,
          timeoutMs: 5_000,
          detail: "no output",
        }),
      ],
    },
    {
      incident:
        "④ semgrep answers, but with a startup failure - which the source reports as \"no findings\"",
      source: "this machine, 2026-11-27: `semgrep --version` -> `CertOpenSystemStore returned NULL` (see live-drill.ts's own comment on it)",
      row: "semgrep answers inside its budget",
      expect: "red",
      verdicts: [
        judgeSemgrepAnswer({
          kind: "error",
          elapsedMs: 900,
          timeoutMs: 5_000,
          detail: "Fatal error: exception Failure: ca_certs_iter_on_anchors: CertOpenSystemStore returned NULL",
        }),
      ],
    },
    {
      incident: "④ `semgrep_kill_ms = 975` rests on one observation, and the pin says so",
      source: "artifacts/preregistration.json frozen.budgets.semgrep_derivation",
      row: "semgrep floor has a distribution",
      expect: "red",
      verdicts: [judgeSemgrepFloor(frozen)],
    },

    // ⑤ a run cannot name its commit -----------------------------------------
    {
      incident: "⑤ the 2026-11-14 run records no commit; 'which code' is unanswerable",
      source: "runs/live/eval-ds-2.0.0-20261114T132232/run.json - top-level keys as recorded",
      row: "run records its commit",
      expect: "na",
      verdicts: [judgeRunRepo({ created_at: "2026-11-14T13:22:32+08:00", repo: null })],
    },
    {
      incident: "⑤ a run staged after recording began that still has no commit is refused",
      source: `repo recording started ${REPO_RECORDING_SINCE}`,
      row: "run records its commit",
      expect: "red",
      verdicts: [judgeRunRepo({ created_at: "2026-11-28T01:00:00+08:00", repo: null })],
    },
    {
      incident: "⑤ a run staged from a dirty tree records a commit that no clone contains",
      source: "the commit would look authoritative; the content it measured exists nowhere",
      row: "run records its commit",
      expect: "red",
      verdicts: [
        judgeRunRepo({
          created_at: "2026-11-28T01:00:00+08:00",
          repo: { commit: "8defdde0000000000000000000000000000000", dirty: true, dirty_files: 3 },
        }),
      ],
    },

    // #43 line 3 grouping ----------------------------------------------------
    {
      incident: "#43 line 3 grouped by sample name, merging B4 and B4g into one timeline",
      source: "perSample keyed on sample alone: recurred 4, unfixed 25 before the re-key",
      row: "line 3 groups one run of one sample",
      expect: "red",
      verdicts: judgePairGrouping(
        [
          { baseline: "B4", sample: "ts-cwe798-0001" },
          { baseline: "B4g", sample: "ts-cwe798-0001" },
        ],
        (row) => String(row.sample),
      ),
    },
    {
      incident: "#43 control: keying on (baseline, sample) separates the two runs",
      source: "line3PairKey(baseline, sample) = `${baseline}\\u0000${sample}`",
      row: "line 3 groups one run of one sample",
      expect: "green",
      verdicts: judgePairGrouping([
        { baseline: "B4", sample: "ts-cwe798-0001" },
        { baseline: "B4g", sample: "ts-cwe798-0001" },
      ]),
    },

    // #43 / #51 rows source --------------------------------------------------
    {
      incident: "#43 bare acceptance.ts on a run directory leaves rowsSource=unknown",
      source: "report rendered `source=unknown` where the staged evaluate gives `source=live`",
      row: "line 4 knows where its rows came from",
      expect: "red",
      verdicts: judgeRowsSource({ rowsSource: "unknown", runJsonPresent: true }),
    },

    // #45-#48 defect spans ---------------------------------------------------
    {
      incident: "#45-#48 `defects[].lines` read as the span: every row came back in_defect false",
      source: "the real field is line_start/line_end; the wrong read did not throw",
      row: "dataset defects carry line_start/line_end",
      expect: "red",
      verdicts: judgeDefectSpans([
        { id: "ts-cwe79-0001", defects: [{ file: "videoHandler.ts", lines: [12, 14], cwe: "CWE-79" }] },
      ]),
    },

    // 2026-11-18 truncated run ----------------------------------------------
    {
      incident: "a capped pass is a prefix, not a result, and N/5 was published from it anyway",
      source: "docs/live-drill.md, 'A capped pass is a prefix, not a result (2026-11-18)'",
      row: "a truncated run publishes no score",
      expect: "red",
      verdicts: judgeTruncatedRun({ truncated: true, gateScorePublished: true }),
    },

    // recorded hashes vs shipped bytes ---------------------------------------
    {
      incident:
        "a pinned rules hash described the CRLF working copy; no checkout could satisfy it, so semgrep returned no findings everywhere else",
      source:
        "first CI run 45955954086: 9 SemgrepSource tests degraded with rules_sha256; pin 612934ee (278490 B) vs blob ab8998b6 (268608 B)",
      row: "every recorded hash matches the tracked bytes",
      expect: "red",
      verdicts: judgeHashAgreement([
        contentRecord({ text: CRLF_RULES, pin: sha256(CRLF_RULES) }),
      ]),
    },
    {
      incident:
        "a recorded size disagrees with the shipped size, even though the hash was never the thing that broke",
      source: "snapshot/manifest.json records 486251 bytes for rules.yaml against a 468950-byte blob",
      row: "every recorded hash matches the tracked bytes",
      expect: "red",
      verdicts: judgeHashAgreement([
        record({ sha256: "aaaa", blobSha: "aaaa", blobBytes: 468950, bytes: 486251, workSha: "zzzz" }),
      ]),
    },
    {
      incident: "control: a record whose hash and size both describe the tracked bytes passes",
      source: "the state after `git add --renormalize` on the eight files the gate named",
      row: "every recorded hash matches the tracked bytes",
      expect: "green",
      verdicts: judgeHashAgreement([
        record({ sha256: "612934ee", blobSha: "612934ee", blobBytes: 278490, bytes: 278490, workSha: "612934ee" }),
      ]),
    },
    {
      // The fix for the fixture above, replayed through the same judge. The pin is
      // a literal, exactly as it sits in `configs/*.json`; the tracked file is the
      // CRLF form. Drop the fold from `contentSha256` and the resolved content
      // becomes the CRLF hash, the literal stops matching, and this goes red.
      incident:
        "control: a rule pin taken over the content matches whichever line endings the checkout produced",
      source:
        "contentSha256 folds CRLF to LF, so a CRLF checkout of the same rules lands on the same pin",
      row: "every recorded hash matches the tracked bytes",
      expect: "green",
      verdicts: judgeHashAgreement([contentRecord({ text: CRLF_RULES, pin: CRLF_RULES_CONTENT_SHA })]),
    },
  ];
}

/** A resolved record with only the fields the check reads. */
function record(parts: {
  sha256: string;
  blobSha: string | null;
  blobBytes: number | null;
  bytes?: number;
  workSha: string | null;
  workBytes?: number | null;
}): ResolvedRecord {
  return {
    path: "research/semgrep-bench/snapshot/py_block.yaml",
    source: "configs/b4.json",
    // The byte view: the pin is a claim about emitted bytes, so the content
    // columns are never read for this kind.
    kind: "bytes",
    sha256: parts.sha256,
    blobSha: parts.blobSha,
    blobBytes: parts.blobBytes,
    blobContentSha: null,
    blobContentBytes: null,
    workSha: parts.workSha,
    workBytes: parts.workBytes ?? parts.blobBytes,
    workContentSha: null,
    ...(parts.bytes === undefined ? {} : { bytes: parts.bytes }),
  };
}

/**
 * A record whose pin is a claim about the rule text, resolved from the text the
 * checkout actually holds - both views computed from it, so a change to the
 * normalisation shows up here rather than being assumed away.
 */
function contentRecord(parts: { text: string; pin: string }): ResolvedRecord {
  const raw = Buffer.from(parts.text, "utf8");
  const folded = Buffer.from(parts.text.replace(/\r\n/g, "\n"), "utf8");
  const rawSha = sha256(raw.toString("utf8"));
  return {
    path: "research/semgrep-bench/snapshot/py_block.yaml",
    source: "configs/b4.json",
    kind: "content",
    sha256: parts.pin,
    blobSha: rawSha,
    blobBytes: raw.length,
    blobContentSha: contentSha256(parts.text),
    blobContentBytes: folded.length,
    workSha: rawSha,
    workBytes: raw.length,
    workContentSha: contentSha256(parts.text),
  };
}

function main(): void {
  const cases = replays();
  const failures: string[] = [];
  const rows: string[] = [];
  for (const replay of cases) {
    const { state, detail } = stateOf(replay.verdicts, replay.row);
    const caught = state === replay.expect;
    if (!caught) failures.push(`${replay.incident}\n     wanted ${replay.expect}, got ${state}: ${detail}`);
    const label = replay.expect === "green" ? "control" : replay.expect === "na" ? "na     " : "red    ";
    rows.push(
      `${caught ? "OK  " : "MISS"} [${label}] ${replay.row}\n` +
        `     incident: ${replay.incident}\n` +
        `     source:   ${replay.source}\n` +
        `     got ${state}: ${detail.slice(0, 200)}`,
    );
  }
  process.stdout.write(
    `GATE REPLAY - every check is fed its incident and has to go red\n\n` +
      `${rows.join("\n\n")}\n\n` +
      (failures.length === 0
        ? `all ${cases.length} replays landed on the expected state\n`
        : `${failures.length}/${cases.length} replays did NOT land:\n  ` + failures.join("\n  ") + "\n"),
  );
  if (failures.length > 0) process.exitCode = 1;
}

if (
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/gate-replay.ts") ||
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/gate-replay.js")
) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  }
}
