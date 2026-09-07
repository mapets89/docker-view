import eslint from "@eslint/js";
import { defineConfig } from "eslint/config";
import tseslint from "typescript-eslint";
export default defineConfig(
  { ignores: ["dist/**", "node_modules/**", ".astro/**"] },
  eslint.configs.recommended,
  ...tseslint.configs.strict,
  {
    files: ["**/*.ts"],
    rules: { "@typescript-eslint/no-non-null-assertion": "off" },
  },
);
