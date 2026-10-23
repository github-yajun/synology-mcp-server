/**
 * Path traversal protection utility.
 * All user-supplied file paths must pass through sanitizePath() before use.
 */

import path from 'node:path';
import { ValidationError } from '../errors.js';

/**
 * Roots a Drive path may address.
 *
 * Without this bound, `sanitizePath()` only blocks `..` traversal, so a path
 * such as `/homes/otheruser/secret.txt` or `/volume2/private` would pass
 * through and be forwarded to DSM. The DSM account's own permissions are the
 * last line of defence, but the MCP server should not be usable to probe
 * paths the operator never intended to expose.
 *
 * These are Synology's standard shared-space roots. `SYNO_DRIVE_ROOTS`
 * overrides the list for deployments that use non-standard share names.
 */
const DEFAULT_DRIVE_ROOTS = ['/mydrive', '/team-folders', '/home'];

/** Reads the operator-configured root list, falling back to the defaults. */
function configuredRoots(): string[] {
  const raw = process.env['SYNO_DRIVE_ROOTS'];
  if (raw === undefined || raw.trim() === '') return DEFAULT_DRIVE_ROOTS;
  const list = raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s !== '')
    .map((s) => (s.startsWith('/') ? s : `/${s}`));
  return list.length > 0 ? list : DEFAULT_DRIVE_ROOTS;
}

/**
 * Sanitizes a Drive path by normalising it and rejecting any traversal attempt.
 *
 * Rules enforced:
 * - Rejects paths containing `..` segments after normalization.
 * - Rejects empty strings.
 * - Preserves leading `/` (Drive paths are absolute).
 * - Rejects paths that fall outside the configured Drive roots.
 *
 * @param p - Raw path string from user input.
 * @returns Normalized, safe path.
 * @throws {ValidationError} When traversal, empty input, or an out-of-root path is detected.
 */
export function sanitizePath(p: string): string {
  if (!p || p.trim() === '') {
    throw new ValidationError('INVALID_PATH', 'Path must not be empty');
  }

  // Check raw input for `..` segments BEFORE normalize: `path.normalize`
  // resolves `..` and would silently let a traversal escape the parent dir.
  const segments = p.split(/[\\/]+/);
  if (segments.some((seg) => seg === '..')) {
    throw new ValidationError(
      'PATH_TRAVERSAL',
      "Path traversal not allowed: path must not contain '..' segments",
    );
  }

  // Safe to normalize once traversal segments are rejected
  const normalized = path.normalize(p);

  // Reject paths outside the permitted Drive roots. The comparison is done
  // on the normalized path so `/mydrive/../etc` style inputs (already caught
  // above) and redundant separators cannot smuggle a path past the check.
  const roots = configuredRoots();
  const inRoot = roots.some((root) => normalized === root || normalized.startsWith(`${root}/`));
  if (!inRoot) {
    throw new ValidationError(
      'PATH_OUT_OF_SCOPE',
      `Path is outside the permitted Drive roots (${roots.join(', ')})`,
    );
  }

  return normalized;
}
