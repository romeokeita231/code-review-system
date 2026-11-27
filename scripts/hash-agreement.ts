/**
 * Every recorded sha256 has to describe bytes that a checkout can actually
 * produce.
 *
 * This check exists because that stopped being true, twice, and neither time was
 * visible from the machine it was found on.
 *
 *  1. 2026-11-27, the first CI run this repository ever had: nine
 *     `SemgrepSource` tests degraded with `rules_sha256`. All six configs pinned
 *     `snapshot/py_block.yaml` at `612934ee…` - the hash of a CRLF working copy -
 *     while the committed blob was the LF form. On any clean checkout the pin
 *     could not match, so the semgrep source returned `findings: []` for every
 *     scan: the blocking path gone, reported as "no findings".
 *  2. Then the secret gate failed the same way: three exempt-zone anchors in
 *     `artifacts/acceptance/PROVENANCE.md` were computed over CRLF copies.
 *
 * Both were invisible locally, for the same reason: this machine's working copy
 * is the CRLF form, so the pins matched the file on disk and every local run was
 * green. `git status` did not help either - the index carries the working file's
 * CRLF size next to an LF blob, so the stat cache called it unchanged and even a
 * plain `git add` short-circuited (`--renormalize` was needed).
 *
 * So the assertion is not "the hash matches the file". It is: **the hash matches
 * what the next commit ships**, read back out of the index rather than off the
 * disk. The working copy is reported only to explain a failure: when a pin
 * matches the working copy and not the tracked bytes, that is the specific
 * defect, and the message says so instead of leaving the next person to
 * re-derive it.
 *
 * Recorded values are gathered from every place that pins one:
 *   - `configs/*.json` -> `sources.semgrep.subsets[].{path,sha256}`
 *   - `tests/l3/support.ts` -> the same pair in a fixture config
 *   - `research/semgrep-bench/snapshot/manifest.json` -> `artifacts.<name>`, plus
 *     `bytes`, which is a second and independent witness
 *   - `artifacts/acceptance/PROVENANCE.md` -> the `sha256:` anchor column
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { captureBytesSync } from "./capture.js";
import type { GateVerdict } from "./shared.js";

export interface HashRecord {
  /** Repo-relative path of the file the hash is about. */
  path: string;
  sha256: string;
  /** A recorded size, when the record carries one. */
  bytes?: number;
  /** Where the record lives, so a failure points at something editable. */
  source: string;
}

export interface ResolvedRecord extends HashRecord {
  /** sha256 of the bytes the index ships for this path. */
  blobSha: string | null;
  blobBytes: number | null;
  /** sha256 of the working copy, only ever used to explain a mismatch. */
  workSha: string | null;
  workBytes: number | null;
}

function sha256Bytes(bytes: Buffer): string {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * The bytes the next commit would ship: the **index** blob, not `HEAD` and not
 * the file on disk.
 *
 * `HEAD` was the first version and it made the gate impossible to satisfy before
 * committing: restore the bytes, stage them, and the check stayed red until the
 * commit existed. A gate that is red while the fix is correct teaches people to
 * ignore it. The index is the right witness - it is what a commit would ship, so
 * it is green as soon as the fix is staged, and it equals `HEAD` on a clean tree.
 */
export function trackedBytes(repo: string, path: string): Buffer | null {
  const result = captureBytesSync("git", ["cat-file", "blob", `:${path}`], {
    cwd: repo,
    timeoutMs: 60_000,
  });
  return result.exitCode === 0 ? result.bytes : null;
}

export function resolveRecord(repo: string, record: HashRecord): ResolvedRecord {
  const absolute = join(repo, record.path);
  const blob = trackedBytes(repo, record.path);
  const work = existsSync(absolute) ? readFileSync(absolute) : null;
  return {
    ...record,
    blobSha: blob === null ? null : sha256Bytes(blob),
    blobBytes: blob === null ? null : blob.length,
    workSha: work === null ? null : sha256Bytes(work),
    workBytes: work === null ? null : work.length,
  };
}

/**
 * The verdict. Red when a recorded hash does not describe the tracked bytes,
 * or when the committed size disagrees with a recorded size.
 */
export function judgeHashAgreement(records: readonly ResolvedRecord[]): GateVerdict {
  const name = "every recorded hash matches the tracked bytes";
  const missing: string[] = [];
  const disagree: string[] = [];
  const workOnly: string[] = [];

  for (const record of records) {
    if (record.blobSha === null) {
      missing.push(`${record.path} (pinned by ${record.source}) is not tracked`);
      continue;
    }
    const hashOk = record.blobSha === record.sha256;
    const sizeOk =
      record.bytes === undefined || record.blobBytes === null || record.bytes === record.blobBytes;
    if (hashOk && sizeOk) continue;
    if (record.workSha === record.sha256) {
      // The specific defect: the pin describes this machine's checkout.
      workOnly.push(
        `${record.path} (${record.source}): the pin ${record.sha256.slice(0, 12)} is the ` +
          `working copy; the index ships ${record.blobSha.slice(0, 12)}` +
          (record.bytes !== undefined && record.blobBytes !== record.bytes
            ? `, ${record.bytes} bytes recorded against ${record.blobBytes}`
            : ""),
      );
    } else {
      disagree.push(
        `${record.path} (${record.source}): recorded ${record.sha256.slice(0, 12)}, ` +
          `the index ships ${record.blobSha.slice(0, 12)}`,
      );
    }
  }

  const problems = missing.length + workOnly.length + disagree.length;
  if (problems === 0) {
    return { name, ok: true, detail: `${records.length} recorded hash(es) agree with the index` };
  }
  return {
    name,
    ok: false,
    detail:
      [
        workOnly.length === 0
          ? ""
          : `${workOnly.length} pin(s) describe the working copy, which no checkout reproduces: ` +
            workOnly.join("; ") +
            `. Restore the bytes (\`git add --renormalize\`) or recompute the pin - but decide ` +
            `which, because the archived measurements were taken against one of the two forms`,
        disagree.length === 0 ? "" : `${disagree.length} recorded hash(es) match neither form: ${disagree.join("; ")}`,
        missing.length === 0 ? "" : `${missing.length} record(s) point at a path HEAD does not have: ${missing.join("; ")}`,
      ]
        .filter((part) => part.length > 0)
        .join(". "),
  };
}

/** Gather every recorded hash this repository carries. */
export function collectRecords(repo: string): HashRecord[] {
  const records: HashRecord[] = [];
  const configsDir = join(repo, "configs");
  for (const name of readdirSync(configsDir).filter((entry) => entry.endsWith(".json"))) {
    const raw = JSON.parse(readFileSync(join(configsDir, name), "utf8")) as {
      sources?: { semgrep?: { subsets?: Array<{ path?: unknown; sha256?: unknown }> } };
    };
    for (const subset of raw.sources?.semgrep?.subsets ?? []) {
      if (typeof subset.path === "string" && typeof subset.sha256 === "string") {
        records.push({ path: subset.path, sha256: subset.sha256, source: `configs/${name}` });
      }
    }
  }

  const supportPath = join(repo, "tests", "l3", "support.ts");
  if (existsSync(supportPath)) {
    const text = readFileSync(supportPath, "utf8");
    for (const match of text.matchAll(
      /path:\s*"([^"]+)",\s*\r?\n\s*sha256:\s*"([0-9a-f]{64})"/g,
    )) {
      records.push({
        path: match[1] ?? "",
        sha256: match[2] ?? "",
        source: "tests/l3/support.ts",
      });
    }
  }

  const manifestPath = join(repo, "research", "semgrep-bench", "snapshot", "manifest.json");
  if (existsSync(manifestPath)) {
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as {
      artifacts?: Record<string, { sha256?: unknown; bytes?: unknown }>;
      rules_yaml_sha256?: unknown;
      rules_yaml_bytes?: unknown;
    };
    for (const [file, entry] of Object.entries(manifest.artifacts ?? {})) {
      if (typeof entry.sha256 !== "string") continue;
      records.push({
        path: `research/semgrep-bench/snapshot/${file}`,
        sha256: entry.sha256,
        ...(typeof entry.bytes === "number" ? { bytes: entry.bytes } : {}),
        source: "snapshot/manifest.json",
      });
    }
    if (typeof manifest.rules_yaml_sha256 === "string") {
      records.push({
        path: "research/semgrep-bench/snapshot/rules.yaml",
        sha256: manifest.rules_yaml_sha256,
        ...(typeof manifest.rules_yaml_bytes === "number" ? { bytes: manifest.rules_yaml_bytes } : {}),
        source: "snapshot/manifest.json (rules_yaml)",
      });
    }
  }

  const provenancePath = join(repo, "artifacts", "acceptance", "PROVENANCE.md");
  if (existsSync(provenancePath)) {
    for (const line of readFileSync(provenancePath, "utf8").split("\n")) {
      const anchor = /sha256:([0-9a-f]{64})/.exec(line);
      if (anchor === null || !line.trimStart().startsWith("|")) continue;
      const cells = line.split("|").map((cell) => cell.trim().replace(/^`|`$/g, ""));
      const path = cells[1] ?? "";
      if (path.length === 0) continue;
      records.push({ path, sha256: anchor[1] ?? "", source: "PROVENANCE.md" });
    }
  }

  return records;
}

async function main(): Promise<void> {
  const repo = process.cwd();
  const records = collectRecords(repo).map((record) => resolveRecord(repo, record));
  const verdict = judgeHashAgreement(records);
  process.stdout.write(
    `HASH AGREEMENT GATE - every recorded sha256 must describe the tracked bytes\n\n` +
      `${verdict.ok ? "PASS" : "FAIL"} ${verdict.name} :: ${verdict.detail}\n`,
  );
  if (!verdict.ok) process.exitCode = 1;
}

if (
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/hash-agreement.ts") ||
  process.argv[1]?.replace(/\\/g, "/").endsWith("scripts/hash-agreement.js")
) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
