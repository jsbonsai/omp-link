#!/usr/bin/env node

// omp-link MCP (Model Context Protocol) stdio server launcher.
//
// Runs the server in `src/mcp-server.ts` so omp-link can be used from Claude Code, Codex CLI,
// Cursor, or anything else that speaks MCP over stdio.
//
// ── Why this file has a loader shim ──────────────────────────────────────────
//
// Every other bin here is plain `.mjs` and imports `src/command-registry.mjs`, a hand-written
// `.mjs` + `.d.mts` pair. That trick works because the registry is dependency-free. It does NOT
// generalise: the MCP server's entire purpose is to drive `LinkNode`, and `src/link-node.ts` plus
// its transitive imports are TypeScript that import each other with `.js` specifiers (the NodeNext
// convention this repo uses). Rewriting `src/mcp-server.ts` as `.mjs` would move the problem one
// file down, not solve it — the `.mjs` would still `import "./link-node.js"`, which does not exist
// on disk.
//
// Node can strip types from `.ts` files (built in since 22.6, on by default since 22.18), but its
// resolver deliberately will not map `./link-node.js` onto `link-node.ts`. That single gap is
// closed below by a ~10-line resolve hook, which needs no dependency and no build step. `tsx`
// (already a devDependency, already required by `npm test`) is the fallback for runtimes with no
// built-in TypeScript support.
//
// Nothing here may write to stdout: stdout belongs to the JSON-RPC stream. Diagnostics go to
// stderr; `--help`/`--version` print and exit before any protocol starts.

// Namespace import, not a named one: `module.register` only exists from Node 20.6, and a missing
// named export is a hard startup crash on the older Node this must still print advice on.
import * as nodeModule from "node:module";
import { spawn } from "node:child_process";

import { EXIT, getVersion } from "../src/command-registry.mjs";

const VERSION = getVersion();

const USAGE = `omp-link-mcp ${VERSION} — MCP stdio server for omp-link

Speaks newline-delimited JSON-RPC 2.0 on stdin/stdout. Intended to be launched by an
MCP host (Claude Code, Codex CLI, Cursor), not run by hand.

Usage:
  omp-link-mcp [options]

Options:
  --name <name>     Terminal name to present on the mesh (default: <link.json name or hostname>-mcp)
  --omp-dir <dir>   State root override, equivalent to OMP_DIR
  -h, --help        Show this help
  -v, --version     Show version

The server attaches to the room already recorded in link.json. Creating and joining rooms
stay human decisions: use \`omp-link create <name>\` or \`omp-link join <ip:port>\`.
`;

function fail(message) {
  process.stderr.write(`omp-link-mcp: ${message}\n`);
  process.exit(EXIT.USAGE);
}

function parseArgs(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "-h" || arg === "--help") return { help: true };
    if (arg === "-v" || arg === "--version") return { version: true };
    if (arg === "--name" || arg === "--omp-dir") {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("-")) {
        fail(`${arg} needs a value. Run omp-link-mcp --help.`);
      }
      if (arg === "--name") options.terminalName = value;
      else options.ompDir = value;
      i++;
      continue;
    }
    fail(`unknown option "${arg}". Run omp-link-mcp --help.`);
  }
  return options;
}

const args = parseArgs(process.argv.slice(2));
if (args.help) {
  process.stdout.write(USAGE);
  process.exit(EXIT.OK);
}
if (args.version) {
  process.stdout.write(`${VERSION}\n`);
  process.exit(EXIT.OK);
}

// A resolve hook, inline as a data: URL so this launcher stays a single file. It only fires when
// normal resolution has already failed, so it can never shadow a real `.js` file.
const JS_TO_TS_HOOK = `data:text/javascript,${encodeURIComponent(`
export async function resolve(specifier, context, nextResolve) {
  try {
    return await nextResolve(specifier, context);
  } catch (err) {
    if (specifier.startsWith(".") && specifier.endsWith(".js")) {
      return await nextResolve(specifier.slice(0, -3) + ".ts", context);
    }
    throw err;
  }
}
`)}`;

const SERVER_URL = new URL("../src/mcp-server.ts", import.meta.url).href;

/** Set on the child of a re-exec, so a runtime that still cannot strip types cannot loop. */
const RESTRIP_MARKER = "OMP_LINK_MCP_RESTRIPPED";

/** True on Node 22.6+, where `--experimental-strip-types` exists even when it is off by default. */
function canFlagStripTypes() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  return major > 22 || (major === 22 && minor >= 6);
}

/**
 * Re-run this exact command with type stripping switched on, wired straight through to the
 * host's pipes. `stdio: "inherit"` means the child owns the real stdin/stdout, so the JSON-RPC
 * stream is untouched; this process becomes a signal relay and nothing else.
 */
function reExecWithStripTypes() {
  // `--no-experimental-strip-types` in execArgv would win over the flag we are adding and the
  // child would fail exactly as the parent did, so it is dropped rather than forwarded.
  const inherited = process.execArgv.filter((a) => a !== "--no-experimental-strip-types");
  const child = spawn(
    process.execPath,
    ["--experimental-strip-types", ...inherited, ...process.argv.slice(1)],
    { stdio: "inherit", env: { ...process.env, [RESTRIP_MARKER]: "1" } },
  );
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.on(signal, () => { try { child.kill(signal); } catch {} });
  }
  child.on("exit", (code, signal) => process.exit(signal ? 1 : code ?? 1));
  child.on("error", (err) => {
    process.stderr.write(`omp-link-mcp: could not re-run node with --experimental-strip-types: ${err.message}\n`);
    process.exit(EXIT.UNAVAILABLE);
  });
}

/**
 * Load the server. Three tiers, cheapest and most portable first; each is exercised by a real
 * run, not assumed.
 *
 * 1. Node's own type stripping plus the resolve hook above. Default from Node 22.18 and 24, so
 *    this is the path a plain `npm i -g omp-link` takes, with no devDependencies present.
 * 2. `tsx`, present in any clone that has run `npm install` or `setup.sh` (it is what `npm test`
 *    already uses), which covers every Node from 18 up.
 * 3. Neither: on Node 22.6-22.17 the stripper exists but is off, so re-run with the flag. Node
 *    below 22.6 has no stripper at all and there is nothing left to try.
 */
async function loadServer() {
  const failures = [];

  if (process.features.typescript) {
    try {
      if (typeof nodeModule.register !== "function") throw new Error("node:module.register is unavailable");
      nodeModule.register(JS_TO_TS_HOOK);
      return await import(SERVER_URL);
    } catch (err) {
      // The loader worked and the sources parsed; something they import is simply not installed.
      // Advising a Node upgrade here would be a confident lie about a broken install.
      if (err?.code === "ERR_MODULE_NOT_FOUND" && !/'tsx/.test(err.message || "")) {
        process.stderr.write(
          `omp-link-mcp: omp-link's dependencies are not installed.\n`
          + `  - ${err.message}\n`
          + `  Fix: run \`npm install\` in the omp-link checkout, or reinstall the package.\n`,
        );
        process.exit(EXIT.UNAVAILABLE);
      }
      failures.push(`node type stripping: ${err?.message || err}`);
    }
  } else {
    failures.push(
      `node ${process.versions.node} has no built-in TypeScript support`
      + " (available from 22.6 with --experimental-strip-types, default from 22.18)",
    );
  }

  try {
    const tsx = await import("tsx/esm/api");
    tsx.register();
    return await import(SERVER_URL);
  } catch (err) {
    failures.push(`tsx: ${err?.message || err}`);
  }

  if (!process.env[RESTRIP_MARKER] && canFlagStripTypes()) {
    process.stderr.write(
      `omp-link-mcp: re-running under node --experimental-strip-types`
      + ` (node ${process.versions.node} has the stripper but not enabled, and tsx is unavailable).\n`,
    );
    reExecWithStripTypes();
    return new Promise(() => {}); // The child owns the stdio from here; this process only relays signals.
  }

  process.stderr.write(
    `omp-link-mcp: cannot load omp-link's TypeScript sources on this runtime.\n`
    + failures.map((f) => `  - ${f}\n`).join("")
    + `  Fix: upgrade to Node 22.18 or newer (\`nvm install --lts\`) — node ${process.versions.node} is below the`
    + ` version that can run TypeScript directly, and Node 20 and earlier are end-of-life.\n`
    + `  Or, in an omp-link git checkout, run \`npm install\` once: that installs tsx, which this launcher will use.\n`,
  );
  process.exit(EXIT.UNAVAILABLE);
}

// Before the import: modules under src/ read the state root through getOmpDir(), and an
// --omp-dir that lands after them would be silently ignored by anything eager.
if (args.ompDir) process.env.OMP_DIR = args.ompDir;

const { startMcpServer } = await loadServer();

startMcpServer({
  terminalName: args.terminalName,
  customOmpDir: args.ompDir,
});
