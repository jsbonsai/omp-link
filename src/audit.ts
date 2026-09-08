import * as fs from "node:fs";
import * as path from "node:path";
import { getOmpDir } from "./identity.js";

export interface AuditRecord {
  type: string;
  timestamp: number;
  [key: string]: any;
}

let customAuditFile: string | null = null;

export function setCustomAuditLogPath(logPath: string | null): void {
  customAuditFile = logPath;
}

export function appendAuditLog(record: AuditRecord): void {
  try {
    const file = customAuditFile || path.join(getOmpDir(), "audit.log");
    const dir = path.dirname(file);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
    }
    const line = JSON.stringify({ ...record, timestamp: record.timestamp || Date.now() }) + "\n";
    fs.appendFileSync(file, line, { mode: 0o600 });
  } catch {}
}

export function readAuditLogs(limit = 100): AuditRecord[] {
  try {
    const file = customAuditFile || path.join(getOmpDir(), "audit.log");
    if (!fs.existsSync(file)) return [];
    const content = fs.readFileSync(file, "utf8");
    const lines = content.split("\n").filter(Boolean);
    const records: AuditRecord[] = [];
    for (const line of lines.slice(-limit)) {
      try {
        records.push(JSON.parse(line));
      } catch {}
    }
    return records;
  } catch {
    return [];
  }
}
