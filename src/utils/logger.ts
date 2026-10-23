/**
 * Minimal structured logger writing single-line JSON to stderr.
 * Sensitive fields in meta objects are redacted via redactSensitive().
 * No external dependencies — intentionally tiny per project constraints.
 */

import { appendFileSync } from 'node:fs';
import { redactSensitive } from './redact.js';

/** Ordered numeric priorities for level filtering. */
const LEVEL_PRIORITY: Record<string, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

/** Public logger interface exposed to consumers. */
export interface Logger {
  /** Emit a debug-level message with optional metadata. */
  debug(msg: string, meta?: Record<string, unknown>): void;
  /** Emit an info-level message with optional metadata. */
  info(msg: string, meta?: Record<string, unknown>): void;
  /** Emit a warn-level message with optional metadata. */
  warn(msg: string, meta?: Record<string, unknown>): void;
  /** Emit an error-level message with optional metadata. */
  error(msg: string, meta?: Record<string, unknown>): void;
}

/** Optional logger configuration. */
export interface LoggerOptions {
  /**
   * Absolute or relative path to a log file. When set, every emitted entry is
   * appended to this file in addition to stderr. File writes are best-effort:
   * a failure must never crash the server.
   */
  filePath?: string;
}

/**
 * Creates a stderr JSON logger filtered to the given minimum level.
 *
 * Output format (one line per message):
 * `{"ts":"<ISO>","level":"info","msg":"...","meta":{...}}`
 *
 * Meta values are deep-cloned and run through `redactSensitive()` before
 * serialization so credentials never appear in logs.
 *
 * @param level - Minimum level to emit. Messages below this are silently dropped.
 * @param opts - Optional file sink configuration.
 * @returns Logger instance.
 */
export function createLogger(
  level: 'debug' | 'info' | 'warn' | 'error',
  opts: LoggerOptions = {},
): Logger {
  const minPriority = LEVEL_PRIORITY[level] ?? 1;
  const filePath = opts.filePath;

  function emit(msgLevel: string, msg: string, meta?: Record<string, unknown>): void {
    const priority = LEVEL_PRIORITY[msgLevel] ?? 1;
    if (priority < minPriority) return;

    const entry: Record<string, unknown> = {
      ts: new Date().toISOString(),
      level: msgLevel,
      msg,
    };

    if (meta !== undefined && Object.keys(meta).length > 0) {
      entry['meta'] = redactSensitive(meta);
    }

    let line: string;
    try {
      line = JSON.stringify(entry) + '\n';
    } catch {
      // Unserializable meta — fall back to a minimal entry rather than crash.
      line =
        JSON.stringify({ ts: entry['ts'], level: msgLevel, msg, meta: '[UNSERIALIZABLE]' }) + '\n';
    }

    try {
      process.stderr.write(line);
    } catch {
      // Suppress serialization errors — never crash the process for logging
    }

    if (filePath !== undefined) {
      try {
        appendFileSync(filePath, line, { encoding: 'utf8', mode: 0o600 });
      } catch {
        // Best-effort file sink — never crash the process for logging
      }
    }
  }

  return {
    debug: (msg, meta) => emit('debug', msg, meta),
    info: (msg, meta) => emit('info', msg, meta),
    warn: (msg, meta) => emit('warn', msg, meta),
    error: (msg, meta) => emit('error', msg, meta),
  };
}
