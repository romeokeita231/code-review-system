import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { zodToJsonSchema } from "zod-to-json-schema";
import { CONTRACT_SCHEMAS } from "../src/contracts/index.js";

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, v]) => v !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, v]) => [k, sortValue(v)]),
    );
  }
  return value;
}

const outDir = join(process.cwd(), "schemas");
await mkdir(outDir, { recursive: true });

for (const [name, schema] of Object.entries(CONTRACT_SCHEMAS)) {
  const json = zodToJsonSchema(schema, { name, target: "jsonSchema7", $refStrategy: "none" });
  const text = `${JSON.stringify(sortValue(json), null, 2)}\n`;
  await writeFile(join(outDir, `${name}.schema.json`), text, "utf8");
}

process.stdout.write(`wrote ${Object.keys(CONTRACT_SCHEMAS).length} schemas\n`);
