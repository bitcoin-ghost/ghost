"use strict";

// Loads the dashboard's real .ts/.tsx modules under `node --test`: a resolve hook for the `@/`
// alias and extensionless relative imports, and a load hook that compiles TypeScript and JSX to
// CommonJS with the project's own `typescript`. Nothing under test is re-implemented here.

const fs = require("node:fs");
const path = require("node:path");
const { pathToFileURL, fileURLToPath } = require("node:url");
const nodeModule = require("node:module");
const ts = require("typescript");

const SRC = path.resolve(__dirname, "..", "..", "src");
const EXTS = [".ts", ".tsx", ".js"];

function withExt(base) {
  if (fs.existsSync(base) && fs.statSync(base).isFile()) return base;
  for (const ext of EXTS) if (fs.existsSync(base + ext)) return base + ext;
  for (const ext of EXTS) if (fs.existsSync(path.join(base, "index" + ext))) return path.join(base, "index" + ext);
  return null;
}

let registered = false;

/** Install the hooks once; returns false where this Node cannot (no `registerHooks`). */
function register() {
  if (registered) return true;
  if (typeof nodeModule.registerHooks !== "function") return false;
  nodeModule.registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier.startsWith("@/")) {
        const f = withExt(path.join(SRC, specifier.slice(2)));
        if (f) return { url: pathToFileURL(f).href, shortCircuit: true };
      }
      if ((specifier.startsWith("./") || specifier.startsWith("../")) && context.parentURL?.startsWith("file:")) {
        const parent = fileURLToPath(context.parentURL);
        if (parent.startsWith(SRC)) {
          const f = withExt(path.resolve(path.dirname(parent), specifier));
          if (f) return { url: pathToFileURL(f).href, shortCircuit: true };
        }
      }
      return nextResolve(specifier, context);
    },
    load(url, context, nextLoad) {
      if (url.startsWith("file:") && /\.tsx?$/.test(url)) {
        const file = fileURLToPath(url);
        const out = ts.transpileModule(fs.readFileSync(file, "utf8"), {
          fileName: file,
          compilerOptions: {
            module: ts.ModuleKind.CommonJS,
            target: ts.ScriptTarget.ES2022,
            jsx: ts.JsxEmit.ReactJSX,
            esModuleInterop: true,
          },
        });
        return { format: "commonjs", source: out.outputText, shortCircuit: true };
      }
      return nextLoad(url, context);
    },
  });
  registered = true;
  return true;
}

/** `require` a module under `src/` by its alias path, e.g. `@/components/nodePool/OverviewView`. */
function load(alias) {
  const f = withExt(path.join(SRC, alias.replace(/^@\//, "")));
  if (!f) throw new Error(`no module at ${alias}`);
  return require(f);
}

module.exports = { register, load, SRC };
