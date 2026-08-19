import { defineConfig } from "tsup";

export default defineConfig({
  entry: [
    "src/index.ts",
    "src/testing/index.ts",
    "src/status-designs/index.ts",
    "src/swiyu-zkp/index.ts",
    "src/swiyu-zkp/sidecar-node.ts",
    "src/swiyu-zkp/native-backend-node.ts",
  ],
  format: ["esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  target: "es2022",
  outDir: "dist",
  splitting: false,
  treeshake: true,
});
