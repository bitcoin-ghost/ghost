import { defineConfig, globalIgnores } from "eslint/config";
import nextVitals from "eslint-config-next/core-web-vitals";
import nextTs from "eslint-config-next/typescript";

const eslintConfig = defineConfig([
  ...nextVitals,
  ...nextTs,
  // The Next 16 react-hooks preset enables React-Compiler-tier rules as errors.
  // This app is NOT built with React Compiler and intentionally uses a couple of
  // idioms those rules flag: a wall-clock read for a time-window filter
  // (`purity`) and the canonical "latest value" ref-sync pattern such as
  // `callbacksRef.current = options` (`refs`). Both are correct here, so keep
  // them as visible warnings rather than build-breaking errors. The genuinely
  // fixable families (`set-state-in-effect`, `immutability`) stay as errors.
  {
    rules: {
      "react-hooks/purity": "warn",
      "react-hooks/refs": "warn",
    },
  },
  // The custom Node server and its test harness are plain CommonJS modules that
  // run outside the Next/browser bundle, so the ESM-only `require` ban does not
  // apply to them.
  {
    files: ["server.js", "tests/**/*.js"],
    rules: {
      "@typescript-eslint/no-require-imports": "off",
    },
  },
  // Override default ignores of eslint-config-next.
  globalIgnores([
    // Default ignores of eslint-config-next:
    ".next/**",
    "out/**",
    "build/**",
    "next-env.d.ts",
    // Vendored, pre-built mempool.space frontend served as static assets — not
    // our source, and the minified bundles must not be linted or reformatted.
    "public/mempool-app/**",
  ]),
]);

export default eslintConfig;
