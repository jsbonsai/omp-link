import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Repo root: fixtures run with this cwd so `--import tsx` resolves the workspace loader. */
export const REPO_ROOT = path.resolve(HERE, "..", "..");
export const FIXTURE_DIR = path.join(HERE, "..", "fixtures");
export const DEFAULT_FIXTURE_TIMEOUT_MS = 20_000;

/**
 * Runs a fixture under a real child `node --import tsx`.
 *
 * Lifecycle faults (an unhandled `error` event, a rejected top-level await, a process that
 * refuses to exit) are invisible to an in-process assertion: the harness that observes them
 * dies with the code under test. Only a separate process can report `exitCode`.
 *
 * `env` is merged over the parent environment. Fixtures MUST confine every write to the state
 * directory the caller passes in (`OMP_DIR` plus the fixture's own `customOmpDir` argument).
 */
export async function runFixture(name, env = {}, timeoutMs = DEFAULT_FIXTURE_TIMEOUT_MS) {
  const fixturePath = path.join(FIXTURE_DIR, name);

  return await new Promise((resolve) => {
    const child = spawn(process.execPath, ["--import", "tsx", fixturePath], {
      cwd: REPO_ROOT,
      env: { ...process.env, ...env },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let spawnError = null;

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });

    const killTimer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);

    child.on("error", (err) => {
      spawnError = err;
    });

    child.on("close", (code, signal) => {
      clearTimeout(killTimer);
      resolve({
        exitCode: code,
        signal,
        stdout,
        stderr,
        timedOut,
        spawnError,
        /** Line-oriented view of stdout; fixtures report structured single-token lines. */
        lines: stdout.split("\n").map((l) => l.trim()).filter(Boolean),
      });
    });
  });
}

/** Renders a captured child result for an assertion message. */
export function describeChildResult(res) {
  return [
    `exitCode=${res.exitCode}`,
    `signal=${res.signal}`,
    `timedOut=${res.timedOut}`,
    `stdout=${JSON.stringify(res.stdout)}`,
    `stderr=${JSON.stringify(res.stderr)}`,
  ].join(" ");
}
