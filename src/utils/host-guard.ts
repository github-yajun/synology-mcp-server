/**
 * Host header validator for MCP SSE / Streamable-HTTP transport.
 *
 * MCP spec (2025-06-18, Streamable HTTP §Security Warning):
 *   Servers MUST validate the `Origin` header on all incoming connections
 *   to prevent DNS rebinding attacks.
 *
 * Origin validation alone is NOT sufficient. In a DNS rebinding attack the
 * victim's browser resolves `evil.com` to a loopback/LAN address and issues a
 * request it considers same-origin, so it may omit `Origin` entirely and
 * skips CORS preflight. The defence needs a second axis: the `Host` header
 * must name an address the operator actually intended to serve, which an
 * attacker-controlled DNS name cannot satisfy.
 *
 * Hostname comparison is port-agnostic (the port in the Host header is
 * chosen by the client and carries no security meaning — an attacker
 * controls the whole header). This matches the MCP SDK's own
 * `hostHeaderValidation` middleware.
 */

/** True for IPv4 127/8, IPv6 ::1, and the literal "localhost". */
function isLoopbackHostname(hostname: string): boolean {
  if (hostname === 'localhost' || hostname === '::1' || hostname === '[::1]') return true;
  return /^127(\.\d{1,3}){3}$/.test(hostname);
}

/** True for wildcard bind addresses (all interfaces). */
function isWildcardBind(host: string): boolean {
  const h = host.trim().toLowerCase();
  return h === '0.0.0.0' || h === '::' || h === '[::]';
}

/**
 * Extracts the hostname portion of a `Host` header value.
 *
 * Handles IPv6 literals (`[::1]:3100` → `[::1]`) and rejects malformed
 * values rather than guessing.
 *
 * @returns The lowercased hostname, or null when the header is malformed.
 */
export function parseHostHeader(hostHeader: string | null | undefined): string | null {
  if (hostHeader === null || hostHeader === undefined) return null;
  const raw = hostHeader.trim().toLowerCase();
  if (raw === '') return null;

  if (raw.startsWith('[')) {
    const end = raw.indexOf(']');
    if (end === -1) return null;
    const hostname = raw.slice(0, end + 1);
    const rest = raw.slice(end + 1);
    // After the bracketed literal only ":port" is valid.
    if (rest !== '' && !/^:\d+$/.test(rest)) return null;
    return hostname;
  }

  const colon = raw.indexOf(':');
  if (colon === -1) return raw;
  const hostname = raw.slice(0, colon);
  const port = raw.slice(colon + 1);
  if (hostname === '') return null;
  if (port !== '' && !/^\d+$/.test(port)) return null;
  return hostname;
}

/**
 * Computes the set of hostnames the server accepts in a `Host` header.
 *
 * - A loopback bind accepts every loopback spelling (127.0.0.0/8, `localhost`,
 *   `::1`), so `127.0.0.1` and `localhost` remain interchangeable.
 * - A specific bind accepts exactly that hostname.
 * - A wildcard bind (0.0.0.0 / ::) accepts the loopback spellings plus any
 *   hostname in `extraAllowedHosts`. It deliberately does NOT accept an
 *   arbitrary Host — that would restore the DNS-rebinding hole. Operators
 *   exposing a wildcard bind on the LAN must list their reachable names via
 *   `MCP_ALLOWED_HOSTS`.
 *
 * @param boundHost - The host the server is bound to.
 * @param extraAllowedHosts - Additional hostnames allowed (e.g. the LAN name).
 */
export function allowedHostnames(boundHost: string, extraAllowedHosts: readonly string[] = []): Set<string> {
  const allowed = new Set<string>();
  const bound = boundHost.trim().toLowerCase();

  if (isWildcardBind(bound)) {
    allowed.add('127.0.0.1');
    allowed.add('localhost');
    allowed.add('::1');
    allowed.add('[::1]');
    for (const h of extraAllowedHosts) {
      const parsed = parseHostHeader(h);
      if (parsed !== null) allowed.add(parsed);
    }
    return allowed;
  }

  if (isLoopbackHostname(bound)) {
    // Any 127.x.x.x address is the same loopback interface.
    allowed.add('127.0.0.1');
    allowed.add('localhost');
    allowed.add('::1');
    allowed.add('[::1]');
    for (const h of extraAllowedHosts) {
      const parsed = parseHostHeader(h);
      if (parsed !== null) allowed.add(parsed);
    }
    return allowed;
  }

  allowed.add(bound);
  for (const h of extraAllowedHosts) {
    const parsed = parseHostHeader(h);
    if (parsed !== null) allowed.add(parsed);
  }
  return allowed;
}

/**
 * Returns true when the request's `Host` header names a permitted host.
 *
 * @param hostHeader - Raw `Host` header value (or null/undefined).
 * @param allowedHosts - Hostnames permitted (as produced by `allowedHostnames()`).
 */
export function isHostAllowed(
  hostHeader: string | null | undefined,
  allowedHosts: ReadonlySet<string>,
): boolean {
  const hostname = parseHostHeader(hostHeader);
  if (hostname === null) return false;

  if (allowedHosts.has(hostname)) return true;

  // Treat any 127.x.x.x address as loopback when loopback is permitted.
  if (/^127(\.\d{1,3}){3}$/.test(hostname) && allowedHosts.has('127.0.0.1')) {
    return true;
  }

  return false;
}
