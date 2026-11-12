import { cp, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import { verifyDataset } from "../../scripts/verify-dataset.js";

const DATASET = fileURLToPath(new URL("../../datasets/self-built", import.meta.url));
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

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("verifyDataset", () => {
  it("accepts the committed dataset", async () => {
    const result = await verifyDataset(DATASET);
    expect(result.errors).toEqual([]);
    expect(result.ok).toBe(true);
  });

  it("reports content hash drift and root drift after tampering", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const names = (await readdir(join(dir, "samples"))).filter((name) => name.endsWith(".json")).sort();
    const target = join(dir, "samples", names[0]!);
    const sample = await readJson<Record<string, unknown>>(target);
    sample.after = `${String(sample.after)}const drifted = true;\n`;
    await writeJson(target, sample);

    const result = await verifyDataset(dir);
    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.includes("content hash mismatch"))).toBe(true);
    expect(result.errors.some((error) => error.includes("root hash drift"))).toBe(true);
  });

  it("reports split leakage when a paired sample moves split", { timeout: 30000 }, async () => {
    const dir = await copyDataset();
    const manifestPath = join(dir, "manifest.json");
    const manifest = await readJson<{
      samples: Array<{ sample_id: string; split: string; paired_safe: boolean }>;
    }>(manifestPath);
    const main = manifest.samples.find((sample) => !sample.paired_safe && sample.split === "fit");
    expect(main).toBeDefined();
    const flipped = main!.split === "fit" ? "eval" : "fit";
    main!.split = flipped;

    const samplePath = join(dir, "samples", `${main!.sample_id}.json`);
    const sample = await readJson<Record<string, unknown>>(samplePath);
    sample.split = flipped;
    await writeJson(samplePath, sample);
    await writeJson(manifestPath, manifest);

    const result = await verifyDataset(dir);
    expect(result.ok).toBe(false);
    expect(result.errors.some((error) => error.includes("split leakage"))).toBe(true);
  });
});
