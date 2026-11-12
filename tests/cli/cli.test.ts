import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ReviewRow } from "../../src/contracts/index.js";
import { configHash, loadConfig } from "../../src/config/index.js";

describe("cli review", () => {
  it("writes one contract-valid JSONL row for a fixed fixture", async () => {
    const dir = mkdtempSync(join(tmpdir(), "crs-cli-"));
    const jsonl = join(dir, "review.jsonl");
    const output = execFileSync(
      process.platform === "win32" ? "npx.cmd" : "npx",
      ["tsx", "src/entry/cli.ts", "review", "--config", "configs/b4g.json", "--event", "tests/fixtures/events/pre-write.json", "--jsonl", jsonl],
      { encoding: "utf8", shell: process.platform === "win32" },
    );
    const line = output.trim().split("\n").filter(Boolean).at(-1)!;
    const parsed = ReviewRow.safeParse(JSON.parse(line));
    expect(parsed.success).toBe(true);
    const row = parsed.data!;
    expect(row.config_hash).toBe(configHash(await loadConfig("configs/b4g.json")));
    expect(row.baseline).toBe("B4g");
    expect(row.mode).toBe("replay");
    expect(row.change_event.id).toBe("evt-0001");
    expect(row.pre_decision).not.toBe("deny");
    expect(readFileSync(jsonl, "utf8").trim().split("\n")).toHaveLength(1);
  }, 60000);

  it("fails loudly on a missing config", () => {
    expect(() =>
      execFileSync(
        process.platform === "win32" ? "npx.cmd" : "npx",
        ["tsx", "src/entry/cli.ts", "review", "--config", "configs/nope.json", "--event", "tests/fixtures/events/pre-write.json"],
        { encoding: "utf8", shell: process.platform === "win32", stdio: "pipe" },
      ),
    ).toThrow(/cannot read config/);
  }, 60000);
});
