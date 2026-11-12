import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { appendRow, readJsonl, writeJsonl } from "../../src/l5/index.js";
import { readFile } from "node:fs/promises";

describe("jsonl", () => {
  it("writes sorted keys with LF endings and no trailing spaces", async () => {
    const dir = await mkdtemp(join(tmpdir(), "crs-jsonl-"));
    const path = join(dir, "rows.jsonl");
    await writeJsonl(path, [{ b: 2, a: 1 }, { z: { y: 1, x: 2 } }]);
    const text = await readFile(path, "utf8");
    expect(text).toBe('{"a":1,"b":2}\n{"z":{"x":2,"y":1}}\n');
    expect(text.includes("\r")).toBe(false);
    for (const line of text.split("\n")) expect(line).toBe(line.replace(/[ \t]+$/, ""));
  });

  it("round-trips rows in order", async () => {
    const dir = await mkdtemp(join(tmpdir(), "crs-jsonl-"));
    const path = join(dir, "rows.jsonl");
    const rows = [{ run_id: "r", n: 1 }, { run_id: "r", n: 2 }];
    await writeJsonl(path, rows);
    expect(await readJsonl(path)).toEqual(rows);
  });

  it("appends one row per line", async () => {
    const dir = await mkdtemp(join(tmpdir(), "crs-jsonl-"));
    const path = join(dir, "rows.jsonl");
    await writeJsonl(path, [{ a: 1 }]);
    await appendRow(path, { a: 2 });
    expect(await readJsonl<{ a: number }>(path)).toEqual([{ a: 1 }, { a: 2 }]);
  });

  it("writes an empty file for no rows", async () => {
    const dir = await mkdtemp(join(tmpdir(), "crs-jsonl-"));
    const path = join(dir, "empty.jsonl");
    await writeJsonl(path, []);
    expect(await readJsonl(path)).toEqual([]);
  });
});
