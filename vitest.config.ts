import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      "@biosecurity/contracts": resolve("packages/contracts/src/index.ts"),
      "@biosecurity/safety": resolve("packages/safety/src/index.ts"),
      "@biosecurity/agent-adapters": resolve("packages/agent-adapters/src/index.ts"),
    },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 15_000,
    hookTimeout: 15_000,
    coverage: {
      reporter: ["text", "json-summary"],
      include: ["packages/**/*.ts", "apps/cli/src/**/*.ts", "apps/server/src/**/*.ts"],
    },
  },
});
