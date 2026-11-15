/**
 * Two-layer secret gate.
 *
 * `.github/secret_scanning.yml` exempts the three zones that hold external bytes
 * - `datasets/`, `research/` and `artifacts/acceptance/` - from GitHub's secret
 * scanning. Once a zone is exempt, a pattern check inside it cannot be the
 * control any more: the exemption exists precisely because the bytes there are
 * upstream copies that legitimately contain client-side keys. That leaves one
 * thing that can take the pattern's place, and it is not optional: **where the
 * bytes came from**.
 *
 *   layer 1 (blocking)   outside the three zones, any provider shape fails.
 *   layer 2 (recorded + blocking)  inside the zones, every file that carries a
 *                        provider shape must be registered in
 *                        `artifacts/acceptance/PROVENANCE.md`: who introduced
 *                        it, where its bytes came from, and an anchor that can
 *                        be recomputed. Unregistered, or registered without a
 *                        recomputable anchor, fails.
 *
 * Layer 2's report is not a courtesy. A gate that can only say "found something
 * in a zone nobody scans" is a switch with no verdict; the registration is what
 * turns a hit into a traceable copy or a leak.
 *
 * The registry lives inside an exempt zone and is the gate's own input, so it
 * could certify itself by being edited. The anchor column is what stops that: a
 * `sha256:` anchor is recomputed here against the file on disk, so editing the
 * bytes without the table - or the table without the bytes - fails. `bytes:` is
 * the weaker version of the same idea, and `upstream:` records a claim this gate
 * cannot check offline but a reader can.
 *
 * `derived:<path>` is the fourth route and the only one that points at another
 * registry row: a copy of key bytes that has no external home. It is not a free
 * pass - the gate follows the chain to its terminal row (at most
 * `MAX_DERIVED_DEPTH` hops), and fails on an unregistered target, a cycle, or a
 * chain that never ends. What a chain proves is narrow and is stated as such in
 * the registry: these bytes are the bytes of that anchored file; whether that
 * file is what its own `upstream:` row claims is a human check.
 *
 * The pattern set is deliberately the union of the shapes that appear in this
 * repository's own history plus the shapes a reviewer would expect: a single
 * provider's shape cannot stand in for a scan (the first version of this gate
 * looked for `sk-` and missed the three `AIza` alerts GitHub raised a day later).
 */
import { execa } from "execa";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { posix } from "node:path";

export interface ProviderShape {
  /** Short name used in reports and in the provenance registry. */
  readonly provider: string;
  /** The shape, with the `g` flag so `String#match` returns every occurrence. */
  readonly pattern: RegExp;
  /** What the shape belongs to, for the report rather than for matching. */
  readonly label: string;
}

export const PROVIDER_SHAPES: readonly ProviderShape[] = [
  { provider: "sk", pattern: /sk-[A-Za-z0-9_-]{20,}/g, label: "OpenAI-style API key" },
  { provider: "AIza", pattern: /AIza[0-9A-Za-z_-]{35}/g, label: "Google / Firebase web key" },
  { provider: "ghp", pattern: /ghp_[A-Za-z0-9]{36}/g, label: "GitHub personal access token" },
  { provider: "github_pat", pattern: /github_pat_[A-Za-z0-9_]{20,}/g, label: "GitHub fine-grained token" },
  { provider: "xox", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/g, label: "Slack token" },
  { provider: "AKIA", pattern: /AKIA[0-9A-Z]{16}/g, label: "AWS access key id" },
  {
    provider: "PRIVATE KEY",
    pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g,
    label: "PEM private key header",
  },
];

/**
 * The zones `.github/secret_scanning.yml` exempts. Kept as prefixes with a
 * trailing slash so `datasets2/` cannot match `datasets/`, and mirrored there:
 * if one list moves, the gate is measuring a different repository than the one
 * GitHub is scanning.
 */
export const EXEMPT_ZONES: readonly string[] = ["datasets/", "research/", "artifacts/acceptance/"];

export const REGISTRY_PATH = "artifacts/acceptance/PROVENANCE.md";

/** Files above this size are not read; the count is reported instead of hidden. */
export const MAX_SCANNED_BYTES = 8_000_000;

export interface Hit {
  readonly path: string;
  readonly provider: string;
  /** Occurrences, not lines: one line can hold three keys. */
  readonly count: number;
  /** Distinct values: three keys repeated are three values and eight occurrences. */
  readonly distinct: number;
}

export interface ProvenanceEntry {
  readonly path: string;
  readonly providers: readonly string[];
  /** Repository the bytes came from. */
  readonly repo: string;
  /** `self@<sha>`: the commit that put the file into this repository. */
  readonly introducedBy: string;
  /** `upstream:` | `url:` | `synthetic:` | `derived:` and the route itself. */
  readonly byteOrigin: string;
  /** For `derived:` rows: the repository-relative path of the row it copies. */
  readonly derivedFrom?: string;
  /** `sha256:<hex>` | `bytes:<n>` | `upstream:<repo>@<sha>[:<path>]`. */
  readonly anchor: string;
  readonly note: string;
}

/** What the gate can recompute about a file: its own hash and size. */
export interface FileFacts {
  readonly sha256: string;
  readonly bytes: number;
}

export interface GateCheck {
  readonly name: string;
  readonly ok: boolean;
  readonly detail: string;
}

export function isExempt(path: string): boolean {
  const normalised = path.replaceAll("\\", "/");
  return EXEMPT_ZONES.some((zone) => normalised.startsWith(zone));
}

/** Occurrences and distinct values per provider in one file. */
export function scanText(text: string): Map<string, { count: number; distinct: number }> {
  const found = new Map<string, { count: number; distinct: number }>();
  for (const shape of PROVIDER_SHAPES) {
    // `String#match` with `g` returns every occurrence and leaves `lastIndex` at
    // zero, so a shared RegExp cannot carry state between files.
    const matches = text.match(shape.pattern);
    if (matches !== null && matches.length > 0) {
      found.set(shape.provider, { count: matches.length, distinct: new Set(matches).size });
    }
  }
  return found;
}

export function scanFiles(
  files: readonly { path: string; text: string; skipped?: boolean }[],
): { hits: Hit[]; skipped: string[] } {
  const hits: Hit[] = [];
  const skipped: string[] = [];
  for (const file of files) {
    if (file.skipped === true) {
      skipped.push(file.path);
      continue;
    }
    for (const [provider, { count, distinct }] of scanText(file.text)) {
      hits.push({ path: file.path, provider, count, distinct });
    }
  }
  return { hits, skipped };
}

const INTRODUCED_BY = /^self@[0-9a-f]{7,40}$/i;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const UPSTREAM = /^upstream:([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)@([0-9a-f]{7,40})(?::(\S+))?$/i;
const BYTE_ORIGIN = /^(upstream|url|synthetic|derived):(\S.*)$/i;
const DERIVED = /^derived:(\S+)$/i;
const SHA256_ANCHOR = /^sha256:([0-9a-f]{64})$/i;
const BYTES_ANCHOR = /^bytes:(\d+)$/i;

/**
 * How many `derived:` rows the gate follows before it stops and calls the chain
 * unproven. Four is not a round number: a registry row derived from a row derived
 * from a row derived from a row is already the longest useful statement ("this
 * copy came from that copy, which came from upstream"), and anything longer
 * describes a build pipeline rather than a provenance.
 */
export const MAX_DERIVED_DEPTH = 4;

/** Repository-relative path, the only form a registry row may name. */
function repoRelative(raw: string): string | null {
  const relative = raw.replaceAll("\\", "/").replace(/^\.\//, "");
  if (relative.length === 0 || posix.isAbsolute(relative) || relative.split("/").includes("..")) return null;
  return relative;
}

function cellsOf(line: string): string[] | null {
  if (!line.trimStart().startsWith("|")) return null;
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const cells = trimmed.split("|").map((cell) => cell.trim());
  return cells.some((cell) => cell.length > 0) ? cells : null;
}

const SEPARATOR = /^:?-{2,}:?$/;
/** The registry's second column is always headed `provider`; no row's value is. */
const PROVIDER_HEADER = "provider";

/** Columns: path | provider | repo | introduced-by | byte-origin | anchor | note. */
export const REGISTRY_COLUMNS = 7;

/**
 * Reads the registry table out of `PROVENANCE.md`.
 *
 * The file also holds hash tables, so the registry is identified by shape rather
 * than by heading: a row with exactly seven cells is a registry row (the hash
 * tables have three). The row whose second cell reads `provider` is the header,
 * and a fully dashed row is the separator. A seven-cell row that does not parse
 * is a *problem*, not a silent skip - a registry that cannot be read is not a
 * registry, and skipping the bad row would turn "someone broke the table" into
 * "that file was never registered", which is the failure this gate exists to
 * report.
 */
export function parseProvenance(markdown: string): {
  entries: ProvenanceEntry[];
  problems: string[];
} {
  const entries: ProvenanceEntry[] = [];
  const problems: string[] = [];
  const lines = markdown.split(/\r?\n/);
  const known = new Set(PROVIDER_SHAPES.map((shape) => shape.provider.toLowerCase()));
  for (const [index, line] of lines.entries()) {
    const cells = cellsOf(line);
    if (cells === null || cells.length !== REGISTRY_COLUMNS) continue;
    if (cells.every((cell) => SEPARATOR.test(cell.replaceAll(" ", "")))) continue;
    if (cells[1]!.toLowerCase() === PROVIDER_HEADER) continue;
    const where = `line ${index + 1}`;
    const [path, providersText, repo, introducedBy, byteOrigin, anchor, note] = cells as [
      string,
      string,
      string,
      string,
      string,
      string,
      string,
    ];
    const relative = repoRelative(path);
    if (relative === null) {
      problems.push(`${where}: "${path}" is not a repository-relative path`);
      continue;
    }
    const providers = providersText
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    const unknown = providers.filter((provider) => !known.has(provider.toLowerCase()));
    if (providers.length === 0 || unknown.length > 0) {
      problems.push(
        `${where}: ${relative} names no known provider` +
          `${unknown.length === 0 ? "" : ` (unknown: ${unknown.join(", ")})`}` +
          `; known: ${[...known].join(", ")}`,
      );
      continue;
    }
    if (!REPO.test(repo)) {
      problems.push(`${where}: ${relative} has no source repository (got "${repo}")`);
      continue;
    }
    if (!INTRODUCED_BY.test(introducedBy)) {
      problems.push(
        `${where}: ${relative} does not say which commit introduced it ` +
          `(got "${introducedBy}", want "self@<sha>")`,
      );
      continue;
    }
    const origin = BYTE_ORIGIN.exec(byteOrigin);
    if (origin === null) {
      problems.push(
        `${where}: ${relative} does not say where its bytes came from (got "${byteOrigin}"; ` +
          `want upstream:<repo>@<sha>:<path>, url:<url>, synthetic:<how> or derived:<path to another row>)`,
      );
      continue;
    }
    if (origin[1]!.toLowerCase() === "upstream" && UPSTREAM.exec(byteOrigin) === null) {
      problems.push(`${where}: ${relative} says upstream but not repo@commit:path (got "${byteOrigin}")`);
      continue;
    }
    if (origin[1]!.toLowerCase() === "derived") {
      // `derived:` names a row, not a recipe: the chain is resolved after every
      // row is read, so a target may be listed below this one.
      const target = DERIVED.exec(byteOrigin);
      if (target === null || repoRelative(target[1]!) === null) {
        problems.push(
          `${where}: ${relative} derives from "${byteOrigin}" but names no repository-relative path ` +
            `(want derived:<path to another row>)`,
        );
        continue;
      }
    }
    if (!hasRecomputableAnchor(anchor)) {
      problems.push(
        `${where}: ${relative} has no recomputable anchor (got "${anchor}"; ` +
          `want sha256:<64 hex>, bytes:<n> or upstream:<repo>@<sha>[:<path>])`,
      );
      continue;
    }
    if (note.length === 0) {
      problems.push(`${where}: ${relative} has no note saying what the bytes are`);
      continue;
    }
    entries.push({
      path: relative,
      providers,
      repo,
      introducedBy,
      byteOrigin,
      anchor,
      note,
      ...(origin[1]!.toLowerCase() === "derived"
        ? { derivedFrom: repoRelative(DERIVED.exec(byteOrigin)![1]!)! }
        : {}),
    });
  }
  return { entries, problems };
}

function hasRecomputableAnchor(anchor: string): boolean {
  return SHA256_ANCHOR.test(anchor) || BYTES_ANCHOR.test(anchor) || UPSTREAM.test(anchor);
}

/**
 * Follows every `derived:` row to the row it names, so a chain cannot be a
 * restatement in disguise.
 *
 * `derived:<path>` means "the key bytes came from that file", and the target
 * must itself be a registered row whose bytes the gate can anchor. Three ways a
 * chain breaks, all of them failures rather than silent stops: the target is not
 * registered (the claim points at nothing), the chain revisits a row (a cycle
 * explains no bytes), or it runs past `MAX_DERIVED_DEPTH` (a pipeline, not a
 * provenance). A chain that resolves ends at a non-`derived` route, which the
 * caller can read back with `derivedChains`.
 */
export function resolveDerivedChains(entries: readonly ProvenanceEntry[]): string[] {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const problems: string[] = [];
  for (const entry of entries) {
    if (!DERIVED.test(entry.byteOrigin)) continue;
    const seen = new Set<string>([entry.path]);
    let current = entry;
    for (;;) {
      const target = DERIVED.exec(current.byteOrigin);
      if (target === null) break; // Terminal row: upstream, url or synthetic.
      if (seen.size > MAX_DERIVED_DEPTH) {
        problems.push(
          `${entry.path}: derived chain exceeds ${MAX_DERIVED_DEPTH} hops (still at ${current.byteOrigin})`,
        );
        break;
      }
      const next = repoRelative(target[1]!)!;
      if (seen.has(next)) {
        problems.push(`${entry.path}: derived chain cycles through ${next}`);
        break;
      }
      const targetEntry = byPath.get(next);
      if (targetEntry === undefined) {
        problems.push(`${entry.path}: derived from ${next}, which is not a registered row`);
        break;
      }
      seen.add(next);
      current = targetEntry;
    }
  }
  return problems;
}

/** One readable line per resolved chain, for the gate's detail. */
export function derivedChains(entries: readonly ProvenanceEntry[]): string[] {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]));
  const lines: string[] = [];
  for (const entry of entries) {
    if (!DERIVED.test(entry.byteOrigin)) continue;
    const path = [entry.path];
    let current = entry;
    for (let hop = 0; hop < MAX_DERIVED_DEPTH; hop += 1) {
      const target = DERIVED.exec(current.byteOrigin);
      if (target === null) break;
      const next = byPath.get(repoRelative(target[1]!) ?? "");
      if (next === undefined) break;
      path.push(next.path);
      current = next;
    }
    lines.push(`${path.join(" -> ")} [${current.byteOrigin.split(":")[0]}]`);
  }
  return lines;
}

/**
 * Checks an anchor against the file on disk where the anchor is about the file.
 *
 * `upstream:` anchors describe someone else's repository and cannot be checked
 * here; the check says it did not verify them rather than calling them verified.
 * A row whose anchor is a hash or a size *is* checked, because that is the only
 * thing that stops this table from certifying itself.
 */
export function checkAnchor(
  entry: ProvenanceEntry,
  facts: FileFacts | undefined,
): { ok: boolean; detail: string; verified: boolean } {
  const sha = SHA256_ANCHOR.exec(entry.anchor);
  if (sha !== null) {
    if (facts === undefined) {
      return { ok: false, detail: "file was not read, so its sha256 cannot be recomputed", verified: false };
    }
    return facts.sha256.toLowerCase() === sha[1]!.toLowerCase()
      ? { ok: true, detail: "sha256 recomputed", verified: true }
      : {
          ok: false,
          detail: `sha256 is ${facts.sha256.slice(0, 16)}..., table says ${sha[1]!.slice(0, 16)}...`,
          verified: true,
        };
  }
  const bytes = BYTES_ANCHOR.exec(entry.anchor);
  if (bytes !== null) {
    if (facts === undefined) {
      return { ok: false, detail: "file was not read, so its size cannot be recomputed", verified: false };
    }
    return facts.bytes === Number(bytes[1])
      ? { ok: true, detail: "size recomputed", verified: true }
      : { ok: false, detail: `file is ${facts.bytes} bytes, table says ${bytes[1]}`, verified: true };
  }
  if (UPSTREAM.test(entry.anchor)) {
    return { ok: true, detail: "upstream claim, not checkable offline", verified: false };
  }
  return { ok: false, detail: "anchor has no recognised form", verified: false };
}

function registryEntry(entries: readonly ProvenanceEntry[], hit: Hit): ProvenanceEntry | undefined {
  const wanted = hit.provider.toLowerCase();
  return entries.find(
    (entry) =>
      entry.path === hit.path &&
      entry.providers.some((provider) => provider.toLowerCase() === wanted || provider === "*"),
  );
}

function describe(hit: Hit): string {
  return `${hit.provider} ${hit.path} ×${hit.count} occurrences / ${hit.distinct} distinct`;
}

/**
 * The three checks, as values.
 *
 * `envKeyMatches` is the old literal check: it matches the *value* of
 * `DEEPSEEK_API_KEY`, so it catches that key even where its shape is not the
 * shape any provider list predicts. `null` means the key was not in the
 * environment, which is the one case where the check cannot run and says so by
 * not appearing at all (the preflight already fails on the missing key).
 *
 * `fileFacts` carries each path's own hash and size, so `sha256:` and `bytes:`
 * anchors are recomputed here instead of believed.
 */
export function evaluateSecretGate(input: {
  hits: readonly Hit[];
  entries: readonly ProvenanceEntry[];
  problems?: readonly string[];
  envKeyMatches?: readonly string[] | null;
  trackedCount: number;
  skipped?: readonly string[];
  fileFacts?: ReadonlyMap<string, FileFacts>;
  /** Resolved `derived:` chains, already followed to their terminal route. */
  derived?: readonly string[];
}): GateCheck[] {
  const checks: GateCheck[] = [];
  const skipped = input.skipped ?? [];

  if (input.envKeyMatches !== null && input.envKeyMatches !== undefined) {
    const matches = input.envKeyMatches;
    checks.push({
      name: "secret not tracked",
      ok: matches.length === 0,
      detail:
        matches.length === 0
          ? `DEEPSEEK_API_KEY not found in ${input.trackedCount} tracked files`
          : `DEEPSEEK_API_KEY appears in ${matches.length} tracked file(s): ${matches.slice(0, 5).join(", ")}`,
    });
  }

  const outside = input.hits.filter((hit) => !isExempt(hit.path));
  checks.push({
    name: "secret outside exempt zones",
    ok: outside.length === 0,
    detail:
      outside.length === 0
        ? `no provider-shaped string outside ${EXEMPT_ZONES.join(", ")} ` +
          `(${input.trackedCount} tracked files, ${PROVIDER_SHAPES.length} providers` +
          `${skipped.length === 0 ? "" : `, ${skipped.length} file(s) over ${MAX_SCANNED_BYTES} bytes not read`})`
        : `${outside.length} unregistered zone(s) carry a provider shape: ` +
          outside.slice(0, 8).map(describe).join("; ") +
          (outside.length > 8 ? `; +${outside.length - 8} more` : "") +
          " - this zone is not exempt from scanning, so the bytes have to go",
  });

  const inside = input.hits.filter((hit) => isExempt(hit.path));
  const unregistered: Hit[] = [];
  const anchorFailures: string[] = [];
  for (const hit of inside) {
    const entry = registryEntry(input.entries, hit);
    if (entry === undefined) {
      unregistered.push(hit);
      continue;
    }
    const anchor = checkAnchor(entry, input.fileFacts?.get(entry.path));
    if (!anchor.ok) {
      anchorFailures.push(`${hit.provider} ${entry.path} (${entry.anchor}): ${anchor.detail}`);
    }
  }
  const problems = input.problems ?? [];
  const verified = input.entries.filter(
    (entry) => checkAnchor(entry, input.fileFacts?.get(entry.path)).verified,
  ).length;
  checks.push({
    name: "secret in exempt zones",
    ok: unregistered.length === 0 && anchorFailures.length === 0 && problems.length === 0,
    detail:
      (inside.length === 0
        ? `no provider-shaped string inside the exempt zones (${input.trackedCount} tracked files)`
        : `${inside.length} file/provider pair(s) recorded and registered: ${inside.map(describe).join("; ")}` +
          ` | ${verified}/${input.entries.length} anchor(s) recomputed here, the rest are upstream claims` +
          (input.derived === undefined || input.derived.length === 0
            ? ""
            : ` | derived: ${input.derived.join("; ")}`)) +
      (problems.length === 0 ? "" : ` | registry problems: ${problems.slice(0, 5).join("; ")}`) +
      (anchorFailures.length === 0 ? "" : ` | anchors that do not recompute: ${anchorFailures.join("; ")}`) +
      (unregistered.length === 0
        ? ""
        : ` | unregistered: ${unregistered
            .slice(0, 8)
            .map(describe)
            .join("; ")}${unregistered.length > 8 ? `; +${unregistered.length - 8} more` : ""}` +
          ` - add a row to ${REGISTRY_PATH} with the byte route and a recomputable anchor`),
  });
  return checks;
}

/**
 * Reads the tracked tree once and runs the three checks.
 *
 * Reading every tracked file is the price of a gate that cannot be dodged by
 * naming a file something the glob does not expect. The literal key comparison
 * needs the raw bytes; the shape scan needs the text. One read serves both.
 */
export async function runSecretGate(
  options: { envKey?: string | null; registryPath?: string; cwd?: string } = {},
): Promise<GateCheck[]> {
  const cwd = options.cwd ?? process.cwd();
  const listed = await execa("git", ["ls-files", "-z"], { cwd, reject: true });
  const paths = `${listed.stdout ?? ""}`.split("\0").filter((file) => file.length > 0);

  const envKey = options.envKey === undefined ? (process.env["DEEPSEEK_API_KEY"] ?? null) : options.envKey;
  const files: { path: string; text: string; skipped: boolean }[] = [];
  const envKeyMatches: string[] = [];
  for (const path of paths) {
    let bytes: Buffer;
    try {
      bytes = await readFile(`${cwd}/${path}`);
    } catch {
      continue;
    }
    if (bytes.length > MAX_SCANNED_BYTES) {
      files.push({ path, text: "", skipped: true });
      continue;
    }
    if (envKey !== null && envKey.length >= 8 && bytes.includes(envKey, 0, "utf8")) {
      envKeyMatches.push(path);
    }
    files.push({ path, text: bytes.toString("utf8"), skipped: false });
  }

  const { hits, skipped } = scanFiles(files);
  const registryPath = options.registryPath ?? `${cwd}/${REGISTRY_PATH}`;
  let markdown = "";
  let registryProblem: string[] = [];
  try {
    markdown = await readFile(registryPath, "utf8");
  } catch {
    registryProblem = [`${REGISTRY_PATH} is missing, so nothing in the exempt zones is traceable`];
  }
  const parsed = markdown.length === 0 ? { entries: [], problems: [] } : parseProvenance(markdown);
  // Chains are resolved after the whole table is read: a `derived:` row may name
  // a row listed below it, and a chain is only meaningful against the full set.
  const derivedProblems = resolveDerivedChains(parsed.entries);

  // Anchors are recomputed from the file itself, so facts are collected for every
  // path the registry talks about - not only for the paths that hit. A file that
  // cannot be read gets no facts, and `checkAnchor` reports the anchor as
  // unrecomputable: a missing file must not look like a verified one.
  const facts = new Map<string, FileFacts>();
  const wanted = new Set([...hits.map((hit) => hit.path), ...parsed.entries.map((entry) => entry.path)]);
  for (const path of wanted) {
    try {
      const bytes = await readFile(`${cwd}/${path}`);
      facts.set(path, { sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.length });
    } catch {
      // Left out on purpose; see above.
    }
  }

  return evaluateSecretGate({
    hits,
    entries: parsed.entries,
    problems: [...registryProblem, ...parsed.problems, ...derivedProblems],
    envKeyMatches: envKey === null ? null : envKeyMatches,
    trackedCount: paths.length,
    skipped,
    fileFacts: facts,
    derived: derivedChains(parsed.entries),
  });
}

async function main(): Promise<void> {
  const checks = await runSecretGate();
  process.stdout.write(
    `${checks.map((check) => `${check.ok ? "OK  " : "FAIL"} ${check.name} :: ${check.detail}`).join("\n")}\n`,
  );
  process.exitCode = checks.every((check) => check.ok) ? 0 : 1;
}

const entry = process.argv[1]?.replaceAll("\\", "/") ?? "";
if (entry.endsWith("scripts/secret-gate.ts") || entry.endsWith("scripts/secret-gate.js")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
