/**
 * File name sanitiser for multipart uploads.
 *
 * Uploaded file names come straight from MCP tool input, which is under the
 * control of the LLM (and therefore of whoever can prompt-inject it). A name
 * is written verbatim into the multipart `Content-Disposition` header, so
 * characters that terminate or split an HTTP header — CR, LF, quotes,
 * backslashes — must be removed before it gets there. This is the class of
 * issue tracked as CVE-2023-28119 / GHSA-hmw2-7cc7-3qxx in `form-data`.
 */

/** True for C0 control characters and DEL. */
function isControlChar(code: number): boolean {
  return code < 0x20 || code === 0x7f;
}

/**
 * Sanitises a user-supplied file name for use as a multipart filename.
 *
 * Rules:
 * - Strips path separators, quotes, and control characters (CR/LF included).
 * - Removes leading dots so the name cannot become `.` or `..`.
 * - Falls back to `file` when nothing usable remains.
 *
 * @param name - Raw file name from tool input.
 * @returns A safe single-segment file name.
 */
export function sanitizeFileName(name: string): string {
  if (typeof name !== 'string') return 'file';

  let cleaned = '';
  for (const ch of name) {
    if (isControlChar(ch.codePointAt(0) ?? 0)) continue;
    if (ch === '"' || ch === '/' || ch === '\\') {
      cleaned += '_';
      continue;
    }
    cleaned += ch;
  }
  cleaned = cleaned.trim();

  // Strip leading dots — prevents "." / ".." and hidden-name semantics.
  cleaned = cleaned.replace(/^\.+/, '');

  if (cleaned === '') return 'file';

  // Cap the length — a filename is a header value, and unbounded names can
  // be used to push headers past server limits.
  if (cleaned.length > 255) {
    cleaned = cleaned.slice(0, 255);
  }

  return cleaned;
}

/**
 * Sanitises a user-supplied MIME type for use as a `Content-Type` value.
 *
 * Only the `type/subtype` shape is kept; parameters are dropped and any
 * character that could terminate or split a header is removed.
 *
 * @param mimeType - Raw MIME type from tool input.
 * @param fallback - Value returned when the input is unusable.
 */
export function sanitizeMimeType(mimeType: string | undefined, fallback = 'application/octet-stream'): string {
  if (mimeType === undefined) return fallback;

  let cleaned = '';
  for (const ch of mimeType) {
    if (isControlChar(ch.codePointAt(0) ?? 0)) continue;
    cleaned += ch;
  }
  cleaned = cleaned.trim();
  if (cleaned === '') return fallback;

  // Keep only the leading `type/subtype`, discard parameters such as
  // `; charset=utf-8`.
  const base = cleaned.split(';')[0]?.trim() ?? '';
  if (!/^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i.test(base)) {
    return fallback;
  }

  return base;
}
