import { createHash } from "node:crypto";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const OUT_DIR = fileURLToPath(new URL("../datasets/self-built", import.meta.url));
const SAMPLE_DIR = join(OUT_DIR, "samples");
const SAMPLE_COUNT_PER_CWE = 30;

const CWES = ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-22", "CWE-502", "CWE-798"] as const;
type Cwe = (typeof CWES)[number];
type Risk = "low" | "medium" | "high";
type Split = "fit" | "eval";

const BASE_RISK: Record<Cwe, Risk> = {
  "CWE-78": "high",
  "CWE-79": "medium",
  "CWE-89": "high",
  "CWE-94": "high",
  "CWE-22": "medium",
  "CWE-502": "high",
  "CWE-798": "low",
};

const EXPECTED_DETECTABLE_BY = ["semgrep", "aor"];

const sha256 = (text: string): string => createHash("sha256").update(text, "utf8").digest("hex");

const splitOf = (groupId: string, cwe: string): Split => {
  const bucket = Number.parseInt(sha256(`${groupId}|${cwe}`).slice(0, 4), 16) % 5;
  return bucket <= 2 ? "fit" : "eval";
};

const bump = (risk: Risk): Risk => (risk === "low" ? "medium" : "high");

const riskOf = (cwe: Cwe, changedLines: number): Risk =>
  changedLines >= 10 ? bump(BASE_RISK[cwe]) : BASE_RISK[cwe];

function diffCount(a: string[], b: string[]): number {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = 1; i <= m; i += 1) {
    for (let j = 1; j <= n; j += 1) {
      if (a[j - 1] === b[i - 1]) {
        dp[i]![j] = dp[i - 1]![j - 1]! + 1;
      } else {
        dp[i]![j] = Math.max(dp[i - 1]![j]!, dp[i]![j - 1]!);
      }
    }
  }
  const lcs = dp[m]![n]!;
  return n + m - 2 * lcs;
}

const camel = (name: string): string =>
  name
    .split("-")
    .map((part, index) => (index === 0 ? part : part.charAt(0).toUpperCase() + part.slice(1)))
    .join("");

interface Block {
  lines: string[];
  label: [number, number];
}

interface Gen {
  fixed: Block;
  vuln: Block;
}

interface Spec {
  module: string;
  names: string[];
  declares: string[];
  ret: string;
  extraArgs?: string;
  normal: (fn: string, arg: string, index: number) => Gen;
  verbose: (fn: string, arg: string, index: number) => Gen;
}

interface Assembled {
  fixed: string[];
  vuln: string[];
  label: [number, number];
}

function assemble(spec: Spec, fn: string, args: string, style: number, gen: Gen): Assembled {
  const signature =
    style === 2
      ? `export const ${fn} = (${args}): ${spec.ret} => {`
      : style === 1
        ? `export async function ${fn}(${args}): Promise<${spec.ret}> {`
        : `export function ${fn}(${args}): ${spec.ret} {`;
  const close = style === 2 ? "};" : "}";
  const head = spec.declares;
  const base = head.length + 2;
  return {
    fixed: [...head, signature, ...gen.fixed.lines, close],
    vuln: [...head, signature, ...gen.vuln.lines, close],
    label: [base + gen.vuln.label[0], base + gen.vuln.label[1]],
  };
}

const ARGS = ["target", "source", "input", "value", "payload", "path", "name", "key", "shard", "topic"];

const OPS_78 = [
  { tool: "tar", args: '"-czf", "/var/data"', plain: "-czf /var/data" },
  { tool: "rsync", args: '"-a", "/srv/mirror"', plain: "-a /srv/mirror" },
  { tool: "ffmpeg", args: '"-i", "/tmp/out"', plain: "-i /tmp/out" },
  { tool: "git", args: '"clone", "origin"', plain: "clone origin" },
  { tool: "gpg", args: '"--output", "/tmp/key"', plain: "--output /tmp/key" },
];

const TAGS_79 = ["h1", "h2", "h3", "strong", "em", "span", "div", "section", "article", "aside"];

const TABLES_89 = [
  "orders",
  "users",
  "invoices",
  "sessions",
  "payments",
  "tickets",
  "events",
  "assets",
  "projects",
  "members",
];

const BASES_22 = [
  "/srv/documents",
  "/var/www/static",
  "/opt/reports",
  "/home/app/files",
  "/data/uploads",
];

const ENDPOINTS_798 = [
  "https://api.internal.example.com",
  "https://billing.example.net/v2",
  "https://mailer.example.org",
  "https://search.example.com",
  "https://storage.example.net",
];

const SECRET_NAMES_798 = [
  "BILLING_API_TOKEN",
  "MAILER_API_KEY",
  "SEARCH_API_TOKEN",
  "STORAGE_API_SECRET",
  "ANALYTICS_API_TOKEN",
];

const SPECS: Record<Cwe, Spec> = {
  "CWE-78": {
    module: "process",
    names: [
      "run-backup",
      "run-deploy",
      "tail-log",
      "sync-assets",
      "publish-site",
      "rotate-keys",
      "dump-database",
      "import-csv",
      "generate-report",
      "upload-artifact",
      "prune-cache",
      "restart-worker",
      "collect-metrics",
      "apply-patch",
      "migrate-schema",
      "build-image",
      "sign-release",
      "fetch-deps",
      "run-lint",
      "package-plugin",
      "seal-archive",
      "restore-snapshot",
      "scan-target",
      "render-video",
      "encode-stream",
      "convert-format",
      "index-corpus",
      "warm-cache",
      "trace-request",
      "flush-queue",
    ],
    declares: [
      "declare function execSyncCommand(command: string): string;",
      "declare function execFileCommand(file: string, args: string[]): string;",
      "declare function logAudit(event: string): void;",
    ],
    ret: "string",
    normal: (fn, arg, index) => {
      const op = OPS_78[index % OPS_78.length]!;
      return {
        fixed: {
          lines: [
            `  const normalized = ${arg}.trim();`,
            `  const result = execFileCommand("${op.tool}", [${op.args}, normalized]);`,
            `  logAudit("${fn}:" + normalized);`,
            "  return result;",
          ],
          label: [1, 2],
        },
        vuln: {
          lines: [
            `  const normalized = ${arg}.trim();`,
            `  const command = "${op.tool} ${op.plain} " + normalized;`,
            "  const result = execSyncCommand(command);",
            `  logAudit("${fn}:" + normalized);`,
            "  return result;",
          ],
          label: [1, 2],
        },
      };
    },
    verbose: (_fn, arg, index) => {
      const op = OPS_78[index % OPS_78.length]!;
      return {
        fixed: {
          lines: [
            `  const toolArgs: string[] = [${op.args}, ${arg}.trim()];`,
            `  const toolName: string = "${op.tool}";`,
            "  const result = execFileCommand(toolName, toolArgs);",
            "  const statusText: string = result.trim();",
            "  return statusText;",
          ],
          label: [0, 2],
        },
        vuln: {
          lines: [
            `  const shellLine: string = "${op.tool} ${op.plain} " + ${arg}.trim();`,
            "  const unsafeRunner = execSyncCommand;",
            "  const rawOutput = unsafeRunner(shellLine);",
            "  const mirroredOutput: string = rawOutput.trim();",
            "  return mirroredOutput;",
          ],
          label: [0, 2],
        },
      };
    },
  },

  "CWE-79": {
    module: "views",
    names: [
      "render-profile",
      "render-comment",
      "render-invoice",
      "render-ticket",
      "render-activity",
      "render-summary",
      "render-notice",
      "render-thread",
      "render-review",
      "render-badge",
      "render-timeline",
      "render-catalog",
      "render-receipt",
      "render-alert",
      "render-digest",
      "render-preview",
      "render-signature",
      "render-caption",
      "render-banner",
      "render-footnote",
      "render-gallery",
      "render-sidebar",
      "render-search",
      "render-portal",
      "render-message",
      "render-snapshot",
      "render-history",
      "render-dashboard",
      "render-widget",
      "render-splash",
    ],
    declares: [
      "declare function escapeHtml(value: string): string;",
      "declare function renderPage(fragment: string): string;",
      "declare function writeResponse(body: string): void;",
    ],
    ret: "string",
    normal: (_fn, arg, index) => {
      const tag = TAGS_79[index % TAGS_79.length]!;
      return {
        fixed: {
          lines: [
            `  const safeText = escapeHtml(${arg});`,
            `  const fragment = "<${tag}>" + safeText + "</${tag}>";`,
            "  const page = renderPage(fragment);",
            "  writeResponse(page);",
            "  return page;",
          ],
          label: [0, 0],
        },
        vuln: {
          lines: [
            `  const fragment = "<${tag}>" + ${arg} + "</${tag}>";`,
            "  const page = renderPage(fragment);",
            "  writeResponse(page);",
            "  return page;",
          ],
          label: [0, 0],
        },
      };
    },
    verbose: (_fn, arg) => ({
      fixed: {
        lines: [
          `  const escapedName: string = escapeHtml(${arg});`,
          `  const escapedBio: string = escapeHtml("bio:" + ${arg});`,
          '  const cardHtml: string = "<article>" + escapedName + escapedBio + "</article>";',
          "  const renderedPage: string = renderPage(cardHtml);",
          "  return renderedPage;",
        ],
        label: [2, 2],
      },
      vuln: {
        lines: [
          `  const rawName: string = ${arg};`,
          `  const rawBio: string = "bio:" + ${arg};`,
          '  const cardMarkup: string = "<article>" + rawName + rawBio + "</article>";',
          "  const responseBody: string = renderPage(cardMarkup);",
          "  return responseBody;",
        ],
        label: [2, 2],
      },
    }),
  },

  "CWE-89": {
    module: "repo",
    names: [
      "find-orders",
      "find-users",
      "find-invoices",
      "find-sessions",
      "find-payments",
      "find-tickets",
      "find-events",
      "find-assets",
      "find-projects",
      "find-members",
      "find-reports",
      "find-files",
      "find-subscriptions",
      "find-messages",
      "find-audits",
      "find-devices",
      "find-agents",
      "find-runs",
      "find-jobs",
      "find-batches",
      "find-records",
      "find-entries",
      "find-items",
      "find-groups",
      "find-labels",
      "find-channels",
      "find-threads",
      "find-schedules",
      "find-quotas",
      "find-tokens",
    ],
    declares: [
      "declare function runQuery(sql: string, params?: unknown[]): Array<Record<string, unknown>>;",
    ],
    ret: "Array<Record<string, unknown>>",
    normal: (_fn, arg, index) => {
      const table = TABLES_89[index % TABLES_89.length]!;
      return {
        fixed: {
          lines: [
            `  const sql = "SELECT id, total FROM ${table} WHERE tenant_id = $1";`,
            `  return runQuery(sql, [${arg}]);`,
          ],
          label: [0, 0],
        },
        vuln: {
          lines: [
            `  const sql = "SELECT id, total FROM ${table} WHERE tenant_id = '" + ${arg} + "'";`,
            "  return runQuery(sql);",
          ],
          label: [0, 0],
        },
      };
    },
    verbose: (_fn, arg, index) => {
      const table = TABLES_89[index % TABLES_89.length]!;
      return {
        fixed: {
          lines: [
            `  const statement: string = "SELECT id, total FROM ${table} WHERE tenant_id = $1 AND status = $2";`,
            `  const params: unknown[] = [${arg}, "active"];`,
            "  const rows = runQuery(statement, params);",
            "  const rowCount: number = rows.length;",
            "  return rows.slice(0, rowCount);",
          ],
          label: [0, 0],
        },
        vuln: {
          lines: [
            `  const statement: string = "SELECT id, total FROM ${table} WHERE tenant_id = '" + ${arg} + "' AND status = 'active'";`,
            "  const looseParams: unknown[] = [];",
            "  const rawRows = runQuery(statement, looseParams);",
            "  const rawCount: number = rawRows.length;",
            "  return rawRows.slice(0, rawCount);",
          ],
          label: [0, 0],
        },
      };
    },
  },

  "CWE-94": {
    module: "expressions",
    names: [
      "compute-formula",
      "evaluate-filter",
      "parse-condition",
      "compile-rule",
      "run-assertion",
      "apply-transform",
      "resolve-mapping",
      "build-predicate",
      "test-expression",
      "execute-snippet",
      "expand-macro",
      "interpret-query",
      "fold-template",
      "reduce-statement",
      "check-invariant",
      "derive-score",
      "score-answer",
      "parse-directive",
      "run-dynamic",
      "materialize-view",
      "compile-template",
      "evaluate-score",
      "resolve-expression",
      "execute-script",
      "expand-shorthand",
      "interpret-clause",
      "transform-input",
      "process-term",
      "calculate-field",
      "render-formula",
    ],
    declares: [
      "declare function normalizeExpression(expression: string): string;",
      "declare function evaluateFormula(expression: string, context: Record<string, number>): number;",
    ],
    ret: "number",
    extraArgs: ", context: Record<string, number>",
    normal: (_fn, arg) => ({
      fixed: {
        lines: [
          `  const expression = normalizeExpression(${arg});`,
          "  return evaluateFormula(expression, context);",
        ],
        label: [0, 1],
      },
      vuln: {
        lines: [
          `  const evaluator = new Function("context", "return (" + ${arg} + ");");`,
          "  return evaluator(context) as number;",
        ],
        label: [0, 1],
      },
    }),
    verbose: (_fn, arg) => ({
      fixed: {
        lines: [
          `  const trimmed: string = ${arg}.trim();`,
          "  const safeExpression: string = normalizeExpression(trimmed);",
          "  const limit: number = 100;",
          "  const value: number = evaluateFormula(safeExpression, context);",
          "  return Math.min(value, limit);",
        ],
        label: [1, 2],
      },
      vuln: {
        lines: [
          `  const source: string = ${arg};`,
          '  const dynamicBody: string = "return (" + source + ");";',
          '  const compiled = new Function("context", dynamicBody);',
          "  const calculated: number = compiled(context) as number;",
          "  return Math.max(calculated, 0);",
        ],
        label: [1, 2],
      },
    }),
  },

  "CWE-22": {
    module: "files",
    names: [
      "load-document",
      "load-avatar",
      "load-attachment",
      "load-export",
      "load-template",
      "load-theme",
      "load-font",
      "load-report",
      "load-certificate",
      "load-backup",
      "load-archive",
      "load-image",
      "load-preview",
      "load-draft",
      "load-manifest",
      "load-changelog",
      "load-license",
      "load-schema",
      "load-preset",
      "load-profile",
      "load-notice",
      "load-readme",
      "load-bundle",
      "load-catalog",
      "load-gallery",
      "load-note",
      "load-snapshot",
      "load-transcript",
      "load-receipt",
      "load-summary",
    ],
    declares: [
      "declare function readTextFile(path: string): string;",
      "declare function joinPath(base: string, name: string): string;",
      "declare function resolvePath(path: string): string;",
    ],
    ret: "string",
    normal: (_fn, arg, index) => {
      const base = BASES_22[index % BASES_22.length]!;
      return {
        fixed: {
          lines: [
            `  const base = "${base}";`,
            `  const target = resolvePath(joinPath(base, ${arg}));`,
            '  if (!target.startsWith(base + "/")) {',
            '    throw new Error("path escapes document root");',
            "  }",
            "  return readTextFile(target);",
          ],
          label: [1, 2],
        },
        vuln: {
          lines: [
            `  const base = "${base}";`,
            `  const target = joinPath(base, ${arg});`,
            "  return readTextFile(target);",
          ],
          label: [1, 2],
        },
      };
    },
    verbose: (_fn, arg, index) => {
      const base = BASES_22[index % BASES_22.length]!;
      return {
        fixed: {
          lines: [
            `  const documentRoot: string = "${base}";`,
            `  const requestedPath: string = joinPath(documentRoot, ${arg});`,
            "  const canonicalPath: string = resolvePath(requestedPath);",
            '  if (!canonicalPath.startsWith(documentRoot + "/")) { throw new Error("path escapes document root"); }',
            "  return readTextFile(canonicalPath);",
          ],
          label: [1, 2],
        },
        vuln: {
          lines: [
            `  const docRoot: string = "${base}";`,
            `  const relativeHit: string = joinPath(docRoot, ${arg});`,
            "  const directHit: string = relativeHit;",
            "  const unverified: string = directHit;",
            "  return readTextFile(unverified);",
          ],
          label: [1, 2],
        },
      };
    },
  },

  "CWE-502": {
    module: "cache",
    names: [
      "restore-session",
      "restore-cart",
      "restore-preferences",
      "restore-permissions",
      "restore-draft",
      "restore-checkpoint",
      "restore-cursor",
      "restore-layout",
      "restore-shortcuts",
      "restore-filters",
      "restore-queue",
      "restore-token",
      "restore-basket",
      "restore-form",
      "restore-history",
      "restore-progress",
      "restore-workspace",
      "restore-tabs",
      "restore-view",
      "restore-state",
      "restore-context",
      "restore-profile",
      "restore-cache",
      "restore-entry",
      "restore-record",
      "restore-payload",
      "restore-envelope",
      "restore-blob",
      "restore-slot",
      "restore-frame",
    ],
    declares: [
      "declare function parseSerialized(payload: string): unknown;",
      "declare function parseJsonStrict(payload: string): unknown;",
      "declare function isSessionRecord(value: unknown): boolean;",
    ],
    ret: "unknown",
    normal: (_fn, arg) => ({
      fixed: {
        lines: [
          `  const raw = ${arg}.trim();`,
          "  const value = parseJsonStrict(raw);",
          "  if (!isSessionRecord(value)) {",
          '    throw new Error("invalid session payload");',
          "  }",
          "  return value;",
        ],
        label: [1, 1],
      },
      vuln: {
        lines: [`  const raw = ${arg}.trim();`, "  return parseSerialized(raw);"],
        label: [1, 1],
      },
    }),
    verbose: (_fn, arg) => ({
      fixed: {
        lines: [
          `  const rawPayload: string = ${arg}.trim();`,
          "  const decoded: unknown = parseJsonStrict(rawPayload);",
          '  if (!isSessionRecord(decoded)) { throw new Error("invalid session payload"); }',
          "  const safeSession: unknown = decoded;",
          "  return safeSession;",
        ],
        label: [1, 1],
      },
      vuln: {
        lines: [
          `  const untrusted: string = ${arg};`,
          "  const revived: unknown = parseSerialized(untrusted);",
          "  const sessionObject: unknown = revived;",
          "  const restored: unknown = sessionObject;",
          "  return restored;",
        ],
        label: [1, 1],
      },
    }),
  },

  "CWE-798": {
    module: "config",
    names: [
      "connect-billing",
      "connect-mailer",
      "connect-search",
      "connect-storage",
      "connect-analytics",
      "connect-cdn",
      "connect-metrics",
      "connect-registry",
      "connect-database",
      "connect-webhook",
      "connect-queue",
      "connect-sms",
      "connect-push",
      "connect-monitor",
      "connect-ledger",
      "connect-crm",
      "connect-erp",
      "connect-auth",
      "connect-proxy",
      "connect-cache",
      "connect-scheduler",
      "connect-vault",
      "connect-identity",
      "connect-sso",
      "connect-ftp",
      "connect-sftp",
      "connect-smtp",
      "connect-nosql",
      "connect-graph",
      "connect-audit",
    ],
    declares: [
      "declare function readSecret(name: string): string;",
      "declare function connectWithToken(endpoint: string, token: string): void;",
    ],
    ret: "void",
    normal: (_fn, _arg, index) => {
      const endpoint = ENDPOINTS_798[index % ENDPOINTS_798.length]!;
      const secretName = SECRET_NAMES_798[index % SECRET_NAMES_798.length]!;
      const secret = `sk_live_${((0x2f9c + index * 2654435761) >>> 0).toString(16).padStart(8, "0")}`;
      return {
        fixed: {
          lines: [
            `  const endpoint = "${endpoint}";`,
            `  const token = readSecret("${secretName}");`,
            "  connectWithToken(endpoint, token);",
          ],
          label: [1, 1],
        },
        vuln: {
          lines: [
            `  const endpoint = "${endpoint}";`,
            `  const token = "${secret}";`,
            "  connectWithToken(endpoint, token);",
          ],
          label: [1, 1],
        },
      };
    },
    verbose: (_fn, _arg, index) => {
      const endpoint = ENDPOINTS_798[index % ENDPOINTS_798.length]!;
      const secretName = SECRET_NAMES_798[index % SECRET_NAMES_798.length]!;
      const secret = `sk_live_${((0x7c31 + index * 1103515245) >>> 0).toString(16).padStart(8, "0")}`;
      return {
        fixed: {
          lines: [
            `  const serviceEndpoint: string = "${endpoint}";`,
            `  const secretName: string = "${secretName}";`,
            "  const accessToken: string = readSecret(secretName);",
            '  const auditLabel: string = "token:" + secretName;',
            "  connectWithToken(serviceEndpoint, accessToken);",
          ],
          label: [2, 2],
        },
        vuln: {
          lines: [
            `  const baseUrl: string = "${endpoint}";`,
            `  const tokenName: string = "${secretName}";`,
            `  const accessToken: string = "${secret}";`,
            '  const clientLabel: string = "token:" + tokenName;',
            "  connectWithToken(baseUrl, accessToken);",
          ],
          label: [2, 2],
        },
      };
    },
  },
};

interface SampleRecord {
  sample_id: string;
  group_id: string;
  split: Split;
  cwe: Cwe;
  risk_level: Risk;
  paired_safe: boolean;
  language: string;
  path: string;
  before: string;
  after: string;
  changed_lines: number;
  expected_detectable_by: string[];
  labels: Array<{ path: string; startLine: number; endLine: number; cwe: string }>;
}

interface ManifestSample {
  sample_id: string;
  group_id: string;
  split: Split;
  cwe: Cwe;
  risk_level: Risk;
  paired_safe: boolean;
  language: string;
  path: string;
  changed_lines: number;
  content_sha256: string;
  expected_detectable_by: string[];
}

const serialize = (value: unknown): string => `${JSON.stringify(value, null, 2)}\n`;

function buildSamples(): SampleRecord[] {
  const records: SampleRecord[] = [];
  for (const cwe of CWES) {
    const spec = SPECS[cwe];
    for (let i = 1; i <= SAMPLE_COUNT_PER_CWE; i += 1) {
      const index = String(i).padStart(2, "0");
      const groupId = `g-${cwe}-${index}`;
      const sampleId = `s-${cwe}-${index}`;
      const split = splitOf(groupId, cwe);
      const name = spec.names[i - 1]!;
      const fn = camel(name);
      const arg = ARGS[i % ARGS.length]!;
      const gen = i % 7 === 0 ? spec.verbose(fn, arg, i) : spec.normal(fn, arg, i);
      const args = `${arg}: string${spec.extraArgs ?? ""}`;
      const assembled = assemble(spec, fn, args, i % 3, gen);
      const path = `src/${spec.module}/${name}.ts`;
      const fixedText = `${assembled.fixed.join("\n")}\n`;
      const vulnText = `${assembled.vuln.join("\n")}\n`;
      const changed = diffCount(assembled.fixed, assembled.vuln);

      records.push({
        sample_id: sampleId,
        group_id: groupId,
        split,
        cwe,
        risk_level: riskOf(cwe, changed),
        paired_safe: false,
        language: "ts",
        path,
        before: fixedText,
        after: vulnText,
        changed_lines: changed,
        expected_detectable_by: [...EXPECTED_DETECTABLE_BY],
        labels: [{ path, startLine: assembled.label[0], endLine: assembled.label[1], cwe }],
      });

      records.push({
        sample_id: `${sampleId}-safe`,
        group_id: groupId,
        split,
        cwe,
        risk_level: riskOf(cwe, 0),
        paired_safe: true,
        language: "ts",
        path,
        before: fixedText,
        after: fixedText,
        changed_lines: 0,
        expected_detectable_by: [...EXPECTED_DETECTABLE_BY],
        labels: [],
      });
    }
  }
  return records;
}

function lineCount(text: string): number {
  const parts = text.split("\n");
  return text.endsWith("\n") ? parts.length - 1 : parts.length;
}

function assertDataset(records: SampleRecord[]): void {
  const expectedTotal = CWES.length * SAMPLE_COUNT_PER_CWE * 2;
  if (records.length !== expectedTotal) {
    throw new Error(`expected ${expectedTotal} samples, got ${records.length}`);
  }

  const groups = new Map<string, SampleRecord[]>();
  for (const record of records) {
    const bucket = groups.get(record.group_id) ?? [];
    bucket.push(record);
    groups.set(record.group_id, bucket);
  }
  if (groups.size !== CWES.length * SAMPLE_COUNT_PER_CWE) {
    throw new Error(`expected ${CWES.length * SAMPLE_COUNT_PER_CWE} groups, got ${groups.size}`);
  }

  for (const [groupId, bucket] of groups) {
    if (bucket.length !== 2) throw new Error(`${groupId}: expected 2 samples, got ${bucket.length}`);
    const main = bucket.find((r) => !r.paired_safe);
    const safe = bucket.find((r) => r.paired_safe);
    if (!main || !safe) throw new Error(`${groupId}: missing main or safe variant`);
    if (safe.sample_id !== `${main.sample_id}-safe`) throw new Error(`${groupId}: safe id mismatch`);
    if (main.split !== safe.split) throw new Error(`${groupId}: split leakage`);
    if (main.cwe !== safe.cwe) throw new Error(`${groupId}: cwe mismatch`);
    if (safe.labels.length !== 0) throw new Error(`${groupId}: safe variant must have no labels`);
    if (main.labels.length !== 1) throw new Error(`${groupId}: main variant must have one label`);
    if (main.labels[0]!.path !== main.path) throw new Error(`${groupId}: label path mismatch`);
    if (main.labels[0]!.endLine > lineCount(main.after)) throw new Error(`${groupId}: label out of bounds`);
    if (main.expected_detectable_by.length === 0) throw new Error(`${groupId}: empty detectable_by`);
  }

  const perCwe = new Map<Cwe, { fit: number; eval: number }>();
  for (const record of records) {
    if (record.paired_safe) continue;
    const bucket = perCwe.get(record.cwe) ?? { fit: 0, eval: 0 };
    bucket[record.split] += 1;
    perCwe.set(record.cwe, bucket);
  }
  let totalFit = 0;
  let total = 0;
  for (const cwe of CWES) {
    const bucket = perCwe.get(cwe);
    if (!bucket) throw new Error(`${cwe}: missing samples`);
    if (bucket.fit === 0 || bucket.eval === 0) throw new Error(`${cwe}: missing a split`);
    if (bucket.fit + bucket.eval !== SAMPLE_COUNT_PER_CWE) throw new Error(`${cwe}: bad count`);
    totalFit += bucket.fit;
    total += bucket.fit + bucket.eval;
  }
  const share = totalFit / total;
  if (share < 0.54 || share > 0.66) {
    throw new Error(`global fit/eval ratio out of band: fit=${totalFit} total=${total}`);
  }
}

async function main(): Promise<void> {
  const records = buildSamples();
  assertDataset(records);

  const entries: ManifestSample[] = records
    .map((record) => ({
      sample_id: record.sample_id,
      group_id: record.group_id,
      split: record.split,
      cwe: record.cwe,
      risk_level: record.risk_level,
      paired_safe: record.paired_safe,
      language: record.language,
      path: record.path,
      changed_lines: record.changed_lines,
      content_sha256: sha256(`${record.before}\u0000${record.after}`),
      expected_detectable_by: record.expected_detectable_by,
    }))
    .sort((a, b) => (a.sample_id < b.sample_id ? -1 : a.sample_id > b.sample_id ? 1 : 0));

  const rootLines = entries.map((entry) => `${entry.sample_id}:${entry.content_sha256}`).sort();
  const manifest = {
    version: "1.0.0",
    content_sha256_root: sha256(rootLines.join("\n")),
    samples: entries,
  };

  await rm(SAMPLE_DIR, { recursive: true, force: true });
  await mkdir(SAMPLE_DIR, { recursive: true });
  const sortedRecords = [...records].sort((a, b) =>
    a.sample_id < b.sample_id ? -1 : a.sample_id > b.sample_id ? 1 : 0,
  );
  for (const record of sortedRecords) {
    await writeFile(join(SAMPLE_DIR, `${record.sample_id}.json`), serialize(record), "utf8");
  }
  await writeFile(join(OUT_DIR, "manifest.json"), serialize(manifest), "utf8");

  const fit = records.filter((r) => !r.paired_safe && r.split === "fit").length;
  const evalCount = records.filter((r) => !r.paired_safe && r.split === "eval").length;
  process.stdout.write(
    `wrote ${records.length} samples (${groupsOf(records)} groups, fit ${fit} / eval ${evalCount}) to ${OUT_DIR}\n`,
  );
}

function groupsOf(records: SampleRecord[]): number {
  return new Set(records.map((record) => record.group_id)).size;
}

await main();
