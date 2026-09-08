import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { execFile } from "node:child_process";

export const SENSITIVE_PATTERNS = [
  /^\.env(\..+)?$/i,
  /id_rsa/i,
  /id_ed25519/i,
  /\.pem$/i,
  /\.key$/i,
  /^\.git([\\/].*)?$/i,
  /[\\/]\.git([\\/].*)?$/i,
  /credentials/i,
  /secrets?(\.json|\.ya?ml)?$/i,
];

const GIT_EXCLUSION_PATHSPECS = [
  ":(exclude).env",
  ":(exclude).env.*",
  ":(exclude)**/*.pem",
  ":(exclude)**/*.key",
  ":(exclude)**/*id_rsa*",
  ":(exclude)**/*id_ed25519*",
  ":(exclude)**/.git",
  ":(exclude)**/credentials*",
  ":(exclude)**/secrets*",
];

export function isSensitivePath(filePath: string): boolean {
  if (!filePath) return true;
  const baseName = path.basename(filePath);
  for (const pattern of SENSITIVE_PATTERNS) {
    if (pattern.test(baseName) || pattern.test(filePath)) {
      return true;
    }
  }
  return false;
}

export function resolveConfinedPath(
  baseDir: string,
  requestedPath: string,
): { allowed: boolean; fullPath?: string; reason?: string } {
  if (!requestedPath || typeof requestedPath !== "string") {
    return { allowed: false, reason: "Missing path parameter" };
  }
  if (requestedPath.includes("\0")) {
    return { allowed: false, reason: "Null bytes forbidden in path" };
  }

  let canonicalBase: string;
  try {
    canonicalBase = fs.realpathSync(baseDir || process.cwd());
  } catch (err: any) {
    return { allowed: false, reason: `Base directory invalid: ${err.message}` };
  }

  const normalizedPath = requestedPath.replace(/\\/g, "/");

  if (/^[a-zA-Z]:/.test(normalizedPath)) {
    return { allowed: false, reason: "Drive letter path escape forbidden" };
  }

  if (isSensitivePath(normalizedPath)) {
    return {
      allowed: false,
      reason: `Access to sensitive file or pattern "${path.basename(normalizedPath)}" is blocked`,
    };
  }

  const candidate = path.isAbsolute(normalizedPath)
    ? path.resolve(normalizedPath)
    : path.resolve(canonicalBase, normalizedPath);

  if (fs.existsSync(candidate)) {
    try {
      const realCandidate = fs.realpathSync(candidate);
      if (
        realCandidate !== canonicalBase &&
        !realCandidate.startsWith(canonicalBase + path.sep)
      ) {
        return {
          allowed: false,
          reason: `Symlink or path traversal escapes workspace root (${canonicalBase})`,
        };
      }
      if (isSensitivePath(realCandidate)) {
        return {
          allowed: false,
          reason: `Access to sensitive file or pattern "${path.basename(realCandidate)}" is blocked`,
        };
      }
      return { allowed: true, fullPath: realCandidate };
    } catch (err: any) {
      return { allowed: false, reason: `Path resolution error: ${err.message}` };
    }
  } else {
    if (candidate !== canonicalBase && !candidate.startsWith(canonicalBase + path.sep)) {
      return { allowed: false, reason: `Path escapes workspace root (${canonicalBase})` };
    }
    return { allowed: true, fullPath: candidate };
  }
}

let cachedGitBinary: string | null = null;

export function resolveTrustedGit(): string {
  if (cachedGitBinary) return cachedGitBinary;

  const candidates = [
    "/usr/bin/git",
    "/opt/homebrew/bin/git",
    "/usr/local/bin/git",
  ];

  for (const c of candidates) {
    try {
      if (fs.existsSync(c)) {
        const stat = fs.statSync(c);
        if (stat.isFile()) {
          cachedGitBinary = c;
          return c;
        }
      }
    } catch {}
  }

  cachedGitBinary = "git";
  return "git";
}

export function safeGitExecFile(
  gitArgs: string[],
  options: { cwd: string; timeout?: number; maxBuffer?: number },
  callback: (err: Error | null, stdout: string, stderr: string, sanitizedEnv: NodeJS.ProcessEnv, finalArgs: string[]) => void,
): void {
  const safeFlags = [
    "-c", "core.fsmonitor=false",
    "-c", "core.pager=cat",
    "-c", "pager.status=false",
    "-c", "pager.diff=false",
    "-c", "pager.log=false",
    "-c", "diff.external=",
  ];

  const cleanEnv: NodeJS.ProcessEnv = { ...process.env };
  const dangerousVars = [
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "NODE_OPTIONS",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_EXEC_PATH",
  ];
  for (const v of dangerousVars) {
    delete cleanEnv[v];
  }
  cleanEnv.GIT_CONFIG_NOSYSTEM = "1";
  cleanEnv.GIT_CONFIG_GLOBAL = os.devNull || "/dev/null";
  cleanEnv.GIT_TERMINAL_PROMPT = "0";

  const gitBin = resolveTrustedGit();
  const finalArgs = [...safeFlags, ...gitArgs];

  execFile(
    gitBin,
    finalArgs,
    {
      cwd: options.cwd || process.cwd(),
      env: cleanEnv,
      maxBuffer: options.maxBuffer || 2 * 1024 * 1024,
      timeout: options.timeout || 10_000,
    },
    (err, stdout, stderr) => {
      callback(
        err,
        stdout ? stdout.toString() : "",
        stderr ? stderr.toString() : "",
        cleanEnv,
        finalArgs,
      );
    },
  );
}

export async function safeGitStatus(cwd: string): Promise<{ ok: boolean; output?: string; error?: string }> {
  return new Promise((resolve) => {
    safeGitExecFile(["status", "--porcelain=v1"], { cwd }, (err, stdout, stderr) => {
      if (err) {
        resolve({ ok: false, error: stderr || err.message });
      } else {
        resolve({ ok: true, output: stdout || "[Working tree clean]" });
      }
    });
  });
}

export async function safeGitDiff(cwd: string): Promise<{ ok: boolean; output?: string; error?: string }> {
  return new Promise((resolve) => {
    // 1. Get changed files
    safeGitExecFile(["diff", "--name-only", "-z"], { cwd }, (err, stdout) => {
      if (err) {
        resolve({ ok: false, error: err.message });
        return;
      }

      const files = stdout.split("\0").filter(Boolean);
      const safeFiles = files.filter((f) => !isSensitivePath(f));

      if (safeFiles.length === 0) {
        resolve({ ok: true, output: "[No non-sensitive changes in working tree]" });
        return;
      }

      // 2. Diff only safe pathspecs
      safeGitExecFile(
        ["diff", "--no-ext-diff", "--no-textconv", "--", ...safeFiles],
        { cwd },
        (diffErr, diffStdout, diffStderr) => {
          if (diffErr) {
            resolve({ ok: false, error: diffStderr || diffErr.message });
          } else {
            resolve({ ok: true, output: diffStdout || "[No diff]" });
          }
        },
      );
    });
  });
}

export async function safeGitLog(
  cwd: string,
  count = 10,
): Promise<{ ok: boolean; output?: string; error?: string }> {
  const boundedCount = Math.max(1, Math.min(100, Math.floor(count)));
  return new Promise((resolve) => {
    safeGitExecFile(
      ["log", `-n${boundedCount}`, "--oneline", "--no-ext-diff"],
      { cwd },
      (err, stdout, stderr) => {
        if (err) {
          resolve({ ok: false, error: stderr || err.message });
        } else {
          resolve({ ok: true, output: stdout || "[No commits]" });
        }
      },
    );
  });
}

export async function safeGitGrep(
  cwd: string,
  query: string,
): Promise<{ ok: boolean; output?: string; error?: string }> {
  if (!query || typeof query !== "string") {
    return { ok: false, error: "Search query required" };
  }
  if (query.length > 512) {
    return { ok: false, error: "Search query exceeds 512 characters maximum limit" };
  }

  const args = [
    "grep",
    "-n",
    "-I",
    "-F",
    "--max-depth=5",
    "-e",
    query,
    "--",
    ".",
    ...GIT_EXCLUSION_PATHSPECS,
  ];

  return new Promise((resolve) => {
    safeGitExecFile(args, { cwd, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        if ((err as any).code === 1) {
          resolve({ ok: true, output: "[No matches found]" });
        } else {
          resolve({ ok: false, error: stderr || err.message });
        }
      } else {
        const lines = stdout.split("\n").filter(Boolean);
        const capped = lines.slice(0, 100);
        let result = capped.join("\n");
        if (lines.length > 100) {
          result += `\n... [${lines.length - 100} additional matches truncated]`;
        }
        resolve({ ok: true, output: result });
      }
    });
  });
}

export async function safeReadFile(
  baseDir: string,
  filePath: string,
  maxBytes = 256 * 1024,
): Promise<{ ok: boolean; content?: string; error?: string; truncated?: boolean }> {
  const confinement = resolveConfinedPath(baseDir, filePath);
  if (!confinement.allowed || !confinement.fullPath) {
    return { ok: false, error: confinement.reason || "Path access denied" };
  }

  try {
    const stat = await fs.promises.stat(confinement.fullPath);
    if (!stat.isFile()) {
      return { ok: false, error: "Target is not a regular file" };
    }

    const readLen = Math.min(stat.size, maxBytes);
    const buf = Buffer.alloc(readLen);
    const fd = await fs.promises.open(confinement.fullPath, "r");
    try {
      await fd.read(buf, 0, readLen, 0);
    } finally {
      await fd.close();
    }

    return {
      ok: true,
      content: buf.toString("utf8"),
      truncated: stat.size > maxBytes,
    };
  } catch (err: any) {
    return { ok: false, error: `Read error: ${err.message}` };
  }
}

export async function safeListDir(
  baseDir: string,
  subPath = "",
  maxEntries = 100,
): Promise<{ ok: boolean; entries?: string[]; error?: string }> {
  const confinement = resolveConfinedPath(baseDir, subPath || ".");
  if (!confinement.allowed || !confinement.fullPath) {
    return { ok: false, error: confinement.reason || "Directory access denied" };
  }

  try {
    const stat = await fs.promises.stat(confinement.fullPath);
    if (!stat.isDirectory()) {
      return { ok: false, error: "Target is not a directory" };
    }

    const items = await fs.promises.readdir(confinement.fullPath, { withFileTypes: true });
    const entries: string[] = [];

    for (const item of items) {
      if (isSensitivePath(item.name)) continue;
      entries.push(item.isDirectory() ? `${item.name}/` : item.name);
      if (entries.length >= maxEntries) break;
    }

    return { ok: true, entries };
  } catch (err: any) {
    return { ok: false, error: `List directory error: ${err.message}` };
  }
}
