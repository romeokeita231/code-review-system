import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { stableStringify } from "../config/index.js";

export function encodeRow(row: unknown): string {
  return stableStringify(row);
}

export async function writeJsonl(path: string, rows: readonly unknown[]): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  const lines = rows.map(encodeRow);
  await writeFile(path, lines.length === 0 ? "" : `${lines.join("\n")}\n`, "utf8");
}

export async function appendRow(path: string, row: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await appendFile(path, `${encodeRow(row)}\n`, "utf8");
}

export async function readJsonl<T = unknown>(path: string): Promise<T[]> {
  const text = await readFile(path, "utf8");
  const rows: T[] = [];
  for (const line of text.split("\n")) {
    const trimmed = line.trim();
    if (trimmed.length === 0) continue;
    rows.push(JSON.parse(trimmed) as T);
  }
  return rows;
}
