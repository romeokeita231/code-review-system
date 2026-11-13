import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { verifyConformance, verifyDataset } from "../../scripts/verify-dataset.js";

const DATASET = fileURLToPath(new URL("../../datasets/self-built", import.meta.url));
const AACR = fileURLToPath(new URL("../../datasets/aacr", import.meta.url));
const tempDirs: string[] = [];

async function copyDataset(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "crs-dataset-"));
  tempDirs.push(root);
  const target = join(root, "dataset");
  await cp(DATASET, target, { recursive: true });
  return target;
}

async function readJson<T>(path: string): Promise<T> {
  return JSON.parse(await readFile(path, "utf8")) as T;
}

const writeJson = async (path: string, value: unknown): Promise<void> => {
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
};

type Row = Record<string, unknown>;

async function sampleIds(dir: string): Promise<string[]> {
  return (await readdir(join(dir, "samples"))).filter((name) => name.endsWith(".json")).sort();
}

/** First row for which `predicate` holds, loaded together with its path. */
async function findRow(
  dir: string,
  predicate: (row: Row) => boolean,
): Promise<{ id: string; path: string; row: Row }> {
  for (const name of await sampleIds(dir)) {
    const path = join(dir, "samples", name);
    const row = await readJson<Row>(path);
    if (predicate(row)) return { id: String(row["sample_id"]), path, row };
  }
  throw new Error("no row matches the predicate");
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("verifyDataset", () => {
  it("accepts the committed ds-2 set and reports its shape", async () => {
    const result = await verifyDataset(DATASET);
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);

    const manifest = await readJson<{ declared: { samples: number; positives: number; negatives: number } }>(
      join(DATASET, "manifest.json"),
    );
    expect(manifest.declared.samples).toBe(34);
    expect(manifest.declared.positives).toBe(26);
    expect(manifest.declared.negatives).toBe(8);
  });

  it("carries at least eight defect-free low-risk rows", async () => {
    const manifest = await readJson<{
      declared: { low_risk_negatives: number; low_risk_negatives_required: number };
    }>(join(DATASET, "manifest.json"));
    expect(manifest.declared.low_risk_negatives).toBeGreaterThanOrEqual(8);
    expect(manifest.declared.low_risk_negatives_required).toBe(8);
  });

  it("fails the gate when the defect-free low-risk pool drops below eight", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    // A whole-file negative is `high` risk again: the diff covers the file, so
    // line 4's eight pairs would silently measure a defective population.
    const target = await findRow(dir, (row) => row["label"] === 0 && String(row["after"]).length > 5000);
    target.row["before"] = "";
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("defect-free low-risk"))).toBe(true);
  });

  it("reports content hash drift and root drift after tampering", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const names = await sampleIds(dir);
    const target = join(dir, "samples", names[0]!);
    const sample = await readJson<Row>(target);
    sample["after"] = `${String(sample["after"])}const drifted = true;\n`;
    await writeJson(target, sample);

    const result = await verifyDataset(dir);
    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.includes("content hash mismatch"))).toBe(true);
    expect(result.errors.some((error) => error.includes("root hash drift"))).toBe(true);
  });

  it("reports a group that crosses the split", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const manifestPath = join(dir, "manifest.json");
    const manifest = await readJson<{ samples: Array<Record<string, unknown>> }>(manifestPath);
    const groups = new Map<string, Array<Record<string, unknown>>>();
    for (const entry of manifest.samples) {
      const key = `${String(entry["group_id"])}`;
      groups.set(key, [...(groups.get(key) ?? []), entry]);
    }
    const pair = [...groups.values()].find((members) => members.length > 1);
    expect(pair).toBeDefined();
    const moved = pair![0]!;
    const flipped = moved["split"] === "fit" ? "eval" : "fit";
    moved["split"] = flipped;

    const samplePath = join(dir, "samples", `${String(moved["sample_id"])}.json`);
    const sample = await readJson<Row>(samplePath);
    sample["split"] = flipped;
    await writeJson(samplePath, sample);
    await writeJson(manifestPath, manifest);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("crosses the split"))).toBe(true);
  });

  it("rejects a defect_origin that calls an upstream defect planted", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    target.row["defect_origin"] = "injected";
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("!= real"))).toBe(true);
  });

  it("rejects a contamination_risk that disagrees with the §10 derivation", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(
      dir,
      (row) => row["repo"] === "juice-shop" && row["label"] === 1,
    );
    target.row["contamination_risk"] = "low";
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(
      result.errors.some((error) => error.includes("!= §10 derivation high")),
    ).toBe(true);
  });

  it("requires defect_origin to be null on a negative row", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 0);
    target.row["defect_origin"] = "injected";
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("carries defect_origin"))).toBe(true);
  });

  it("rejects a hand-written defect id", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    const defects = target.row["defects"] as Array<Record<string, unknown>>;
    defects[0]!["defect_id"] = `${target.id}#d1`;
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes(`should be ${target.id}:d1`))).toBe(true);
  });

  it("hard-rejects an origin that points into the codefixes tree", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    const origin = target.row["origin"] as Record<string, unknown>;
    origin["ref"] = `juice-shop@${String(origin["ref"]).split("@")[1]!.split(":")[0]}:data/static/codefixes/x.ts`;
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("data/static/codefixes/"))).toBe(true);
  });

  it("rejects a rationale that names no control", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    target.row["rationale"] = "已修改";
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("names no control"))).toBe(true);
  });

  it("rejects sample_cwe=null on a row that carries defects", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    target.row["sample_cwe"] = null;
    await writeJson(target.path, target.row);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("row has defects but sample_cwe=null"))).toBe(true);
  });

  it("rejects a negative that shares a file with a positive", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const positive = await findRow(dir, (row) => row["label"] === 1);
    const negative = await findRow(dir, (row) => row["label"] === 0);
    negative.row["repo"] = positive.row["repo"];
    negative.row["file_path"] = positive.row["file_path"];
    negative.row["group_id"] = positive.row["group_id"];
    await writeJson(negative.path, negative.row);

    const result = await verifyDataset(dir);
    expect(
      result.errors.some((error) => error.includes(`negative shares a file with positive ${positive.id}`)),
    ).toBe(true);
  });

  it("rejects a stale declared count", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const manifestPath = join(dir, "manifest.json");
    const manifest = await readJson<{ declared: Record<string, unknown> }>(manifestPath);
    manifest.declared["samples"] = 35;
    await writeJson(manifestPath, manifest);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("declared.samples"))).toBe(true);
  });

  it("refuses an insufficient_n class without a supply record", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const manifestPath = join(dir, "manifest.json");
    const manifest = await readJson<{ declared: { supply_exhausted: Array<Record<string, unknown>> } }>(manifestPath);
    manifest.declared.supply_exhausted = manifest.declared.supply_exhausted.filter((entry) => entry["cwe"] !== "078");
    await writeJson(manifestPath, manifest);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("CWE-078 is insufficient_n without a supply record"))).toBe(true);
  });

  it("requires every searched source in a supply record", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const manifestPath = join(dir, "manifest.json");
    const manifest = await readJson<{ declared: { supply_exhausted: Array<Record<string, unknown>> } }>(manifestPath);
    const record = manifest.declared.supply_exhausted.find((entry) => entry["cwe"] === "918")!;
    record["sources"] = (record["sources"] as unknown[]).slice(0, 2);
    await writeJson(manifestPath, manifest);

    const result = await verifyDataset(dir);
    expect(result.errors.some((error) => error.includes("expected every searched source"))).toBe(true);
  });
});

describe("verifyConformance", () => {
  it("accepts the committed ds-2 set", async () => {
    const result = await verifyConformance(DATASET);
    expect(result.violations).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.samples).toBe(34);
  });

  it("reports a no-op write as a violation", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 0);
    target.row["before"] = target.row["after"];
    await writeJson(target.path, target.row);

    const result = await verifyConformance(dir);
    expect(result.summary.map((group) => group.rule)).toContain("noop");
  });

  it("reports a comment-only diff as no change at all", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 0);
    target.row["before"] = "export const value = 1\n";
    target.row["after"] = "export const value = 1\n// only a comment was added\n";
    await writeJson(target.path, target.row);

    const result = await verifyConformance(dir);
    expect(
      result.violations.some((violation) => violation.rule === "noop" && /comments/.test(violation.detail)),
    ).toBe(true);
  });

  it("reports a defect span outside the changed window", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    const defects = target.row["defects"] as Array<Record<string, unknown>>;
    defects[0]!["line_start"] = 1;
    defects[0]!["line_end"] = 1;
    await writeJson(target.path, target.row);

    const result = await verifyConformance(dir);
    expect(
      result.violations.some((violation) => violation.rule === "defects" && /changed window/.test(violation.detail)),
    ).toBe(true);
  });

  it("reports a class outside §6", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const target = await findRow(dir, (row) => row["label"] === 1);
    target.row["sample_cwe"] = "CWE-502";
    const defects = target.row["defects"] as Array<Record<string, unknown>>;
    defects[0]!["cwe"] = "CWE-502";
    await writeJson(target.path, target.row);

    const result = await verifyConformance(dir);
    expect(result.violations.some((violation) => violation.detail.includes("CWE-502"))).toBe(true);
  });

  it("accepts the imported AACR set", async () => {
    const result = await verifyConformance(AACR);
    expect(result.violations).toEqual([]);
    expect(result.ok).toBe(true);
  });
});
