import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { arg } from "./shared.js";

const runs = resolve(arg("--runs", "runs"));
const out = resolve(arg("--out", "artifacts/report"));
const dataset = resolve(arg("--dataset", "datasets/self-built"));
const result = spawnSync(
  "python",
  ["-m", "crs_eval.cli", "report", "--runs", runs, "--out", out, "--dataset", dataset],
  { cwd: resolve("eval"), encoding: "utf8", shell: process.platform === "win32" },
);
process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");
process.exitCode = result.status ?? 1;
