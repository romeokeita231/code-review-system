import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

const r = (p: string) => fileURLToPath(new URL(p, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      "@contracts": r("./src/contracts/index.ts"),
      "@config": r("./src/config/index.ts"),
      "@l1": r("./src/l1/index.ts"),
      "@l2": r("./src/l2/index.ts"),
      "@l3": r("./src/l3/index.ts"),
      "@l4": r("./src/l4/index.ts"),
      "@l5": r("./src/l5/index.ts"),
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
  },
});
