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
 *                        `artifacts/acceptance/PROVENANCE.md` with the source
 *                        repository and a commit; unregistered fails.
 *
 * Layer 2's report is not a courtesy. A gate that can only say "found something
 * in a zone nobody scans" is a switch with no verdict; the registration is what
 * turns a hit into a traceable copy or a leak.
 *
 * The pattern set is deliberately the union of the shapes that appear in this
 * repository's own history plus the shapes a reviewer would expect: a single
 * provider's shape cannot stand in for a scan (the first version of this gate
 * looked for `sk-` and missed the three `AIza` alerts GitHub raised a day later).
 */
import { execa } from "execa";
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
  readonly count: number;
}

export interface ProvenanceEntry {
  readonly path: string;
  readonly providers: readonly string[];
  readonly repo: string;
  readonly commit: string;
  readonly origin: string;
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

/** Occurrences per provider in one file. Counts, not lines: one line can hold three keys. */
export function scanText(text: string): Map<string, number> {
  const counts = new Map<string, number>();
  for (const shape of PROVIDER_SHAPES) {
    // `String#match` with `g` returns every occurrence and leaves `lastIndex` at
    // zero, so a shared RegExp cannot carry state between files.
    const found = text.match(shape.pattern);
    if (found !== null && found.length > 0) counts.set(shape.provider, found.length);
  }
  return counts;
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
    for (const [provider, count] of scanText(file.text)) {
      hits.push({ path: file.path, provider, count });
    }
  }
  return { hits, skipped };
}

const COMMIT = /^(?:self@)?[0-9a-f]{7,40}$/i;
const REPO = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

function cellsOf(line: string): string[] | null {
  if (!line.trimStart().startsWith("|")) return null;
  const trimmed = line.trim().replace(/^\|/, "").replace(/\|$/, "");
  const cells = trimmed.split("|").map((cell) => cell.trim());
  return cells.some((cell) => cell.length > 0) ? cells : null;
}

const SEPARATOR = /^:?-{2,}:?$/;
/** The registry's second column is always headed `provider`; no row's value is. */
const PROVIDER_HEADER = "provider";

/**
 * Reads the registry table out of `PROVENANCE.md`.
 *
 * The file also holds hash tables, so the registry is identified by shape rather
 * than by heading: a row with exactly five cells is a registry row (the hash
 * tables have three). The row whose second cell reads `provider` is the header,
 * and a fully dashed row is the separator. A five-cell row that does not parse
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
  for (const [index, line] of lines.entries()) {
    const cells = cellsOf(line);
    if (cells === null || cells.length !== 5) continue;
    if (cells.every((cell) => SEPARATOR.test(cell.replaceAll(" ", "")))) continue;
    if (cells[1]!.toLowerCase() === PROVIDER_HEADER) continue;
    const where = `line ${index + 1}`;
    const [path, providersText, repo, commit, origin] = cells as [string, string, string, string, string];
    const relative = path.replaceAll("\\", "/").replace(/^\.\//, "");
    if (relative.length === 0 || posix.isAbsolute(relative) || relative.split("/").includes("..")) {
      problems.push(`${where}: "${path}" is not a repository-relative path`);
      continue;
    }
    const providers = providersText
      .split(",")
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    const known = new Set(PROVIDER_SHAPES.map((shape) => shape.provider.toLowerCase()));
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
    if (!COMMIT.test(commit)) {
      problems.push(`${where}: ${relative} has no commit (got "${commit}")`);
      continue;
    }
    if (origin.length === 0) {
      problems.push(`${where}: ${relative} has no note saying what the bytes are`);
      continue;
    }
    entries.push({ path: relative, providers, repo, commit, origin });
  }
  return { entries, problems };
}

function registryCovers(entries: readonly ProvenanceEntry[], hit: Hit): boolean {
  const wanted = hit.provider.toLowerCase();
  return entries.some(
    (entry) =>
      entry.path === hit.path &&
      entry.providers.some((provider) => provider.toLowerCase() === wanted || provider === "*"),
  );
}

function describe(hit: Hit): string {
  return `${hit.provider} ${hit.path} ×${hit.count}`;
}

/**
 * The three checks, as values.
 *
 * `envKeyMatches` is the old literal check: it matches the *value* of
 * `DEEPSEEK_API_KEY`, so it catches that key even where its shape is not the
 * shape any provider list predicts. `null` means the key was not in the
 * environment, which is the one case where the check cannot run and says so by
 * not appearing at all (the preflight already fails on the missing key).
 */
export function evaluateSecretGate(input: {
  hits: readonly Hit[];
  entries: readonly ProvenanceEntry[];
  problems?: readonly string[];
  envKeyMatches?: readonly string[] | null;
  trackedCount: number;
  skipped?: readonly string[];
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
  const unregistered = inside.filter((hit) => !registryCovers(input.entries, hit));
  const problems = input.problems ?? [];
  checks.push({
    name: "secret in exempt zones",
    ok: unregistered.length === 0 && problems.length === 0,
    detail:
      (inside.length === 0
        ? `no provider-shaped string inside the exempt zones (${input.trackedCount} tracked files)`
        : `${inside.length} file/provider pair(s) recorded and registered: ${inside.map(describe).join("; ")}`) +
      (problems.length === 0 ? "" : ` | registry problems: ${problems.slice(0, 5).join("; ")}`) +
      (unregistered.length === 0
        ? ""
        : ` | unregistered: ${unregistered
            .slice(0, 8)
            .map(describe)
            .join("; ")}${unregistered.length > 8 ? `; +${unregistered.length - 8} more` : ""}` +
          ` - add a row to ${REGISTRY_PATH} with the source repository and commit`),
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

  return evaluateSecretGate({
    hits,
    entries: parsed.entries,
    problems: [...registryProblem, ...parsed.problems],
    envKeyMatches: envKey === null ? null : envKeyMatches,
    trackedCount: paths.length,
    skipped,
  });
}

async function main(): Promise<void> {
  const checks = await runSecretGate();
  process.stdout.write(`${checks.map((check) => `${check.ok ? "OK  " : "FAIL"} ${check.name} :: ${check.detail}`).join("\n")}\n`);
  process.exitCode = checks.every((check) => check.ok) ? 0 : 1;
}

const entry = process.argv[1]?.replaceAll("\\", "/") ?? "";
if (entry.endsWith("scripts/secret-gate.ts") || entry.endsWith("scripts/secret-gate.js")) {
  main().catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
