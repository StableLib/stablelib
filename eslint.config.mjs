import globals from "globals";
import pluginJs from "@eslint/js";
import tseslint from "typescript-eslint";


export default [
  {files: ["**/*.{js,mjs,cjs,ts}"]},
  {languageOptions: { globals: {...globals.browser, ...globals.node} }},
  pluginJs.configs.recommended,
  ...tseslint.configs.recommended,
  {rules: {
    "prefer-const": "off",
    "prefer-spread": "off",
    "no-constant-condition": "off",
    "@typescript-eslint/no-explicit-any": "off",
    "@typescript-eslint/consistent-type-imports": "error",
  }},
];
