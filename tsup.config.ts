import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: {
      index: "src/index.ts",
      cli: "src/entry/cli.ts",
      plugin: "src/entry/plugin.ts"
    },
    format: ["esm"],
    target: "node20",
    dts: true,
    clean: true,
    sourcemap: true,
    splitting: false,
  },
]);
