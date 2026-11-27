#!/usr/bin/env node
/**
 * Run one of this repo's TypeScript entry points **without** a spawning
 * transpiler.
 *
 * `tsx` and `vitest` both start `esbuild`, and esbuild starts its service
 * worker over an IPC pipe. The default DSH sandbox refuses that spawn:
 *
 *   Error: spawn EPERM   errno -4048   syscall: 'spawn'
 *     at ensureServiceIsRunning (esbuild/lib/main.js)
 *     at startSyncServiceWorker (esbuild/lib/main.js)
 *
 * So `npm run wiring:check` and `npm test` exit 1 with a stack trace that says
 * nothing about the repository. A check that cannot start in the environment the
 * agent works in is not a check: it gets reclassified as "broken tooling" and
 * skipped, which is how a one-switch bypass gets reintroduced.
 *
 * `tsc` only reads and writes files, so it runs anywhere. This launcher emits
 * once into `.tmp/run/` and then hands the compiled entry point to plain `node`.
 *
 *   node scripts/run.mjs wiring-check
 *   node scripts/run.mjs instrument-gate --samples 20
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";

const OUT = ".tmp/run";
const name = process.argv[2];
if (name === undefined || name.length === 0) {
  process.stderr.write("usage: node scripts/run.mjs <script-name> [args...]\n");
  process.exit(2);
}

/**
 * Always emit. Deciding staleness by mtime is a second bug of the same shape as
 * the one this launcher exists to avoid: a stale artefact that looks fresh.
 * `tsc -p` over `src` + `scripts` is about five seconds.
 */
const emit = spawnSync(
  process.execPath,
  [
    resolve("node_modules/typescript/bin/tsc"),
    "-p",
    "tsconfig.scripts.json",
    "--outDir",
    OUT,
    "--declaration",
    "false",
    "--noEmit",
    "false",
  ],
  { stdio: "inherit" },
);
if (emit.error) {
  process.stderr.write(`could not start tsc: ${emit.error.message}\n`);
  process.exit(1);
}
if (emit.status !== 0) process.exit(emit.status ?? 1);

const entry = join(OUT, "scripts", `${name}.js`);
if (!existsSync(entry)) {
  process.stderr.write(
    `no entry point for "${name}": expected ${entry}\n` +
      `(the file has to be scripts/${name}.ts and be reachable from tsconfig.scripts.json)\n`,
  );
  process.exit(2);
}

const run = spawnSync(process.execPath, [entry, ...process.argv.slice(3)], { stdio: "inherit" });
if (run.error) {
  process.stderr.write(`could not start node: ${run.error.message}\n`);
  process.exit(1);
}
process.exit(run.status ?? 1);
