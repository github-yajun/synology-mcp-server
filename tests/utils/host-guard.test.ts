import { describe, it, expect } from 'vitest';
import { allowedHostnames, isHostAllowed, parseHostHeader } from '../../src/utils/host-guard.js';

describe('parseHostHeader', () => {
  it('extracts a bare hostname', () => {
    expect(parseHostHeader('nas.local')).toBe('nas.local');
  });

  it('extracts a hostname with a port', () => {
    expect(parseHostHeader('nas.local:3100')).toBe('nas.local');
  });

  it('lowercases the result', () => {
    expect(parseHostHeader('NAS.Local:3100')).toBe('nas.local');
  });

  it('keeps IPv6 literals bracketed', () => {
    expect(parseHostHeader('[::1]:3100')).toBe('[::1]');
    expect(parseHostHeader('[::1]')).toBe('[::1]');
  });

  it('rejects missing or malformed headers', () => {
    expect(parseHostHeader(undefined)).toBeNull();
    expect(parseHostHeader(null)).toBeNull();
    expect(parseHostHeader('')).toBeNull();
    expect(parseHostHeader('   ')).toBeNull();
    expect(parseHostHeader('[::1')).toBeNull();
    expect(parseHostHeader('nas.local:notaport')).toBeNull();
    expect(parseHostHeader(':3100')).toBeNull();
  });
});

describe('allowedHostnames', () => {
  it('permits every loopback spelling for a loopback bind', () => {
    const allowed = allowedHostnames('127.0.0.1');
    expect(allowed.has('127.0.0.1')).toBe(true);
    expect(allowed.has('localhost')).toBe(true);
    expect(allowed.has('::1')).toBe(true);
    expect(allowed.has('[::1]')).toBe(true);
  });

  it('permits only the bound name for a specific bind', () => {
    const allowed = allowedHostnames('nas.local');
    expect(allowed.has('nas.local')).toBe(true);
    expect(allowed.has('evil.example.com')).toBe(false);
    expect(allowed.has('127.0.0.1')).toBe(false);
  });

  it('does not accept arbitrary hosts for a wildcard bind', () => {
    // A wildcard bind must NOT accept any Host header — that would restore
    // the DNS-rebinding hole the guard exists to close.
    const allowed = allowedHostnames('0.0.0.0');
    expect(allowed.has('evil.example.com')).toBe(false);
    expect(allowed.has('127.0.0.1')).toBe(true);
    expect(allowed.has('localhost')).toBe(true);
  });

  it('adds explicitly allowed hosts for a wildcard bind', () => {
    const allowed = allowedHostnames('0.0.0.0', ['nas.local', 'synology:3100']);
    expect(allowed.has('nas.local')).toBe(true);
    expect(allowed.has('synology')).toBe(true);
    expect(allowed.has('evil.example.com')).toBe(false);
  });
});

describe('isHostAllowed', () => {
  const loopback = allowedHostnames('127.0.0.1');
  const specific = allowedHostnames('nas.local');

  it('accepts an exactly matching hostname', () => {
    expect(isHostAllowed('nas.local', specific)).toBe(true);
    expect(isHostAllowed('nas.local:3100', specific)).toBe(true);
  });

  it('rejects an unexpected hostname', () => {
    expect(isHostAllowed('evil.example.com', specific)).toBe(false);
    expect(isHostAllowed('evil.example.com', loopback)).toBe(false);
  });

  it('rejects a missing or malformed Host header', () => {
    expect(isHostAllowed(undefined, loopback)).toBe(false);
    expect(isHostAllowed(null, loopback)).toBe(false);
    expect(isHostAllowed('', loopback)).toBe(false);
  });

  it('treats any 127.x address as loopback when loopback is permitted', () => {
    expect(isHostAllowed('127.0.0.5', loopback)).toBe(true);
  });

  it('does not permit loopback aliases for a specific non-loopback bind', () => {
    expect(isHostAllowed('127.0.0.1', specific)).toBe(false);
  });
});
