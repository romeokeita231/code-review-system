import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
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

/* -------------------------------------------------------------------------
 * Spec conformance (issue #7 §13)
 * ---------------------------------------------------------------------- */

const SPEC_CWES = ["022", "078", "079", "089", "094", "798", "918"];
const LOW_RISK_CLASSES = new Set(["079", "798"]);

const BEFORE = "export function run(input: string) {\n  return query(input);\n}\n";
const AFTER = "export function run(input: string) {\n  return query(\"run \" + input);\n}\n";

/**
 * A dataset that satisfies the spec rather than the current implementation:
 * seven §6 classes, five groups each split 3:2, one defect per positive row,
 * `variant_of` pairing and §9 risk derivation.
 */
async function conformantDataset(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "crs-conformance-"));
  tempDirs.push(root);
  const dir = join(root, "dataset");
  await mkdir(join(dir, "samples"), { recursive: true });
  const manifest = { version: "ds-test", content_sha256_root: "unused", samples: [] as unknown[] };
  let seq = 1;

  for (const cwe of SPEC_CWES) {
    for (let group = 0; group < 5; group += 1) {
      const split = group < 3 ? "fit" : "eval";
      const filePath = `src/${cwe}-${group}.ts`;
      const id = `ts-cwe${cwe}-${String(seq).padStart(4, "0")}`;
      const safeId = `ts-cwe${cwe}-${String(seq + 1).padStart(4, "0")}`;
      seq += 2;
      const risk = LOW_RISK_CLASSES.has(cwe) ? "low" : "high";
      const base = {
        schema_version: 1,
        unit: "file_write",
        language: "ts",
        sample_set: "self",
        group_id: `g-${cwe}-${group}`,
        repo: "nodejs-goof",
        file_path: filePath,
        before: BEFORE,
        after: AFTER,
        sample_cwe: `CWE-${cwe}`,
        expected_detectable_by: "both",
        risk_level: risk,
        contamination_risk: "low",
        annotator: "self",
      };
      const positive = {
        ...base,
        sample_id: id,
        defects: [
          {
            defect_id: `${id}#d1`,
            cwe: `CWE-${cwe}`,
            file: filePath,
            line_start: 2,
            line_end: 2,
            symbol: "run",
            evidence: "input flows into query",
          },
        ],
        variant_of: null,
        origin: { kind: "self_rewritten", ref: id, advisory: null },
      };
      const safe = {
        ...base,
        sample_id: safeId,
        defects: [],
        variant_of: id,
        origin: { kind: "self_rewritten", ref: id, advisory: null },
      };
      for (const row of [positive, safe]) {
        await writeFile(join(dir, "samples", `${row.sample_id}.json`), JSON.stringify(row), "utf8");
        manifest.samples.push({
          ...row,
          split,
          path: row.file_path,
          paired_safe: row === safe,
          changed_lines: 2,
          content_sha256: "unused",
        });
      }
    }
  }
  await writeFile(join(dir, "manifest.json"), JSON.stringify(manifest), "utf8");
  return dir;
}

describe("verifyConformance", () => {
  it("fails the committed dataset and names each drift", async () => {
    const result = await verifyConformance(DATASET);
    expect(result.ok).toBe(false);
    const rules = result.summary.map((group) => group.rule);
    expect(rules).toContain("schema");
    expect(rules).toContain("sample_id");
    expect(rules).toContain("risk_level");
    expect(rules).toContain("classes");
    expect(rules).toContain("split_ratio");
    const schema = result.summary.find((group) => group.rule === "schema");
    expect(schema?.examples.join("\n")).toMatch(/unrecognized keys: .*paired_safe/);
  });

  it("accepts a spec-shaped dataset", async () => {
    const result = await verifyConformance(await conformantDataset());
    expect(result.violations.slice(0, 5)).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.samples).toBe(70);
  });

  it("fails a risk level that ignores §9 and a class outside §6", async () => {
    const dir = await conformantDataset();
    const names = (await readdir(join(dir, "samples"))).filter((name) => name.endsWith(".json")).sort();
    const target = names.find((name) => name.startsWith("ts-cwe022-"));
    const sample = await readJson<Record<string, unknown>>(join(dir, "samples", target!));
    // CWE-022 can never be `low` under §9.
    sample.risk_level = "low";
    await writeJson(join(dir, "samples", target!), sample);

    const stranger: Record<string, unknown> = {
      ...sample,
      sample_id: "ts-cwe502-9999",
      sample_cwe: "CWE-502",
      risk_level: "high",
      defects: [],
      variant_of: null,
    };
    await writeJson(join(dir, "samples", "ts-cwe502-9999.json"), stranger);
    const manifestPath = join(dir, "manifest.json");
    const manifest = await readJson<{ samples: Array<Record<string, unknown>> }>(manifestPath);
    manifest.samples.push({
      ...stranger,
      split: "eval",
      path: stranger["file_path"],
      paired_safe: false,
      changed_lines: 2,
      content_sha256: "x",
    });
    await writeJson(manifestPath, manifest);

    const result = await verifyConformance(dir);
    expect(result.ok).toBe(false);
    const rules = result.summary.map((group) => group.rule);
    expect(rules).toContain("risk_level");
    expect(rules).toContain("classes");
    expect(result.violations.some((violation) => violation.detail.includes("CWE-502"))).toBe(true);
  });

  it("accepts the imported AACR set and keeps its accounting coherent", async () => {
    const result = await verifyConformance(AACR);
    expect(result.violations).toEqual([]);
    expect(result.ok).toBe(true);

    const report = await readJson<{
      counts: Record<string, number>;
      ratio: Record<string, string>;
      samples: Array<{ sample_id: string; arm: string; label: number }>;
    }>(join(AACR, "import-report.json"));
    const manifest = await readJson<{ samples: Array<{ sample_id: string }> }>(join(AACR, "manifest.json"));

    expect(report.counts["imported"]).toBe(report.samples.length);
    expect(report.counts["imported"]).toBe(manifest.samples.length);
    // §3 asks for an equal-sized non-Security control arm.
    expect(report.counts["imported_control_negative"]).toBe(report.counts["imported_positive"]);
    expect(report.ratio["security_stratum"]).toBe(
      `${report.counts["imported_positive"]}:${report.counts["imported_security_negative"]}`,
    );
    const ids = new Set(manifest.samples.map((row) => row.sample_id));
    for (const sample of report.samples) expect(ids.has(sample.sample_id)).toBe(true);
  });
});
