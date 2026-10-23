import { describe, it, expect } from 'vitest';
import { sanitizePath } from '../../src/utils/path-guard.js';
import { ValidationError } from '../../src/errors.js';

describe('sanitizePath', () => {
  it('returns safe absolute paths unchanged', () => {
    expect(sanitizePath('/mydrive')).toBe('/mydrive');
    expect(sanitizePath('/team-folders/reports')).toBe('/team-folders/reports');
  });

  it('normalises redundant separators', () => {
    // path.normalize collapses double slashes
    const result = sanitizePath('/mydrive//docs');
    expect(result).not.toContain('//');
  });

  it('throws ValidationError for traversal with double-dot segment', () => {
    expect(() => sanitizePath('/mydrive/../../etc/passwd')).toThrow(ValidationError);
    expect(() => sanitizePath('../sibling')).toThrow(ValidationError);
  });

  it('throws with code PATH_TRAVERSAL for traversal attempts', () => {
    try {
      sanitizePath('/a/../../../b');
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).code).toBe('PATH_TRAVERSAL');
    }
  });

  it('throws ValidationError for empty string', () => {
    expect(() => sanitizePath('')).toThrow(ValidationError);
  });

  it('throws ValidationError for whitespace-only string', () => {
    expect(() => sanitizePath('   ')).toThrow(ValidationError);
  });

  it('rejects relative paths outside the permitted Drive roots', () => {
    // Relative paths are no longer accepted: every Drive path must live
    // under a configured root (/mydrive, /team-folders, /home).
    expect(() => sanitizePath('reports/q1')).toThrow(ValidationError);
  });

  it('accepts paths under a permitted Drive root', () => {
    expect(sanitizePath('/mydrive/reports/q1')).toBe('/mydrive/reports/q1');
    expect(sanitizePath('/team-folders/reports')).toBe('/team-folders/reports');
  });

  it('rejects paths outside the permitted Drive roots', () => {
    // Path traversal is blocked, but so is any absolute path that does not
    // live under a configured root — otherwise the server could be used to
    // probe other users' spaces or other volumes.
    expect(() => sanitizePath('/homes/otheruser/secret.txt')).toThrow(ValidationError);
    expect(() => sanitizePath('/volume2/private')).toThrow(ValidationError);
    expect(() => sanitizePath('/etc.defaults/VERSION')).toThrow(ValidationError);
  });

  it('reports PATH_OUT_OF_SCOPE for out-of-root paths', () => {
    try {
      sanitizePath('/homes/otheruser/secret.txt');
      expect.fail('expected to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(ValidationError);
      expect((err as ValidationError).code).toBe('PATH_OUT_OF_SCOPE');
    }
  });

  it('does not let a prefix-sharing root bypass the check', () => {
    // '/mydrive-evil' must not be accepted just because '/mydrive' is.
    expect(() => sanitizePath('/mydrive-evil/file.txt')).toThrow(ValidationError);
  });
});
