import { resolve } from "node:path";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  root: resolve(import.meta.dirname),
  plugins: [react()],
  resolve: {
    alias: {
      "@biosecurity/contracts": resolve(
        import.meta.dirname,
        "../../packages/contracts/src/index.ts",
      ),
    },
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: {
      "/api": "http://127.0.0.1:7331",
      "/demo": "http://127.0.0.1:7331",
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: true,
  },
});
