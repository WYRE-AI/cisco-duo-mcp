import { createHash, createHmac } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { signV5Get, stripSecretFields } from '../client.js';

const CREDS = { ikey: 'DIXXXXXXXXXXXXXXXXXX', skey: 'deadbeefcafebabe0123456789abcdef01234567', apiHost: 'API-XXXXXXXX.DuoSecurity.com' };

describe('signV5Get - Duo Auth Signature v5 (HMAC-SHA512)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-08-21T17:29:18.000Z'));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('lowercases the API host in both the signed URL and the request URL', () => {
    const { url } = signV5Get(CREDS, '/admin/v1/users');
    expect(url).toBe('https://api-xxxxxxxx.duosecurity.com/admin/v1/users');
  });

  it('sends an RFC 2822 Date header identical to the timestamp that was signed', () => {
    const { headers } = signV5Get(CREDS, '/admin/v1/users');
    expect(headers.Date).toMatch(/^\w{3}, \d{2} \w{3} \d{4} \d{2}:\d{2}:\d{2} -0000$/);
  });

  it('Authorization is HTTP Basic auth with ikey as the username and a hex HMAC-SHA512 signature as the password', () => {
    const { headers } = signV5Get(CREDS, '/admin/v1/users');
    expect(headers.Authorization.startsWith('Basic ')).toBe(true);
    const decoded = Buffer.from(headers.Authorization.slice('Basic '.length), 'base64').toString('utf8');
    const [ikey, signature] = decoded.split(':');
    expect(ikey).toBe(CREDS.ikey);
    expect(signature).toMatch(/^[0-9a-f]{128}$/); // SHA-512 hex digest is 128 chars
  });

  it('the signature matches an independently-computed 7-line canonical string', () => {
    const { headers, url } = signV5Get(CREDS, '/admin/v1/users', { offset: 20 });
    const date = headers.Date;
    const host = CREDS.apiHost.toLowerCase();
    const sha512Hex = (s: string) => createHash('sha512').update(s, 'utf8').digest('hex');
    const bodyHash = sha512Hex('');
    const headersHash = sha512Hex('');
    const canonical = [date, 'GET', host, '/admin/v1/users', 'offset=20', bodyHash, headersHash].join('\n');
    const expectedSignature = createHmac('sha512', CREDS.skey).update(canonical, 'utf8').digest('hex');
    const decoded = Buffer.from(headers.Authorization.slice('Basic '.length), 'base64').toString('utf8');
    expect(decoded).toBe(`${CREDS.ikey}:${expectedSignature}`);
    expect(url).toBe('https://api-xxxxxxxx.duosecurity.com/admin/v1/users?offset=20');
  });

  it('sorts query params lexicographically by URL-encoded key and drops undefined/null/empty values', () => {
    const { url } = signV5Get(CREDS, '/admin/v1/users', { offset: 5, limit: 10, username: undefined, foo: null });
    // "limit" < "offset" lexicographically
    expect(url).toBe('https://api-xxxxxxxx.duosecurity.com/admin/v1/users?limit=10&offset=5');
  });

  it('a different skey produces a different signature for the identical request', () => {
    const { headers: h1 } = signV5Get(CREDS, '/admin/v1/users');
    const { headers: h2 } = signV5Get({ ...CREDS, skey: 'a-completely-different-secret' }, '/admin/v1/users');
    expect(h1.Authorization).not.toBe(h2.Authorization);
  });

  it('a different path produces a different signature with the same credentials', () => {
    const { headers: h1 } = signV5Get(CREDS, '/admin/v1/users');
    const { headers: h2 } = signV5Get(CREDS, '/admin/v1/phones');
    expect(h1.Authorization).not.toBe(h2.Authorization);
  });
});

describe('stripSecretFields - defensive safety net for any secret-shaped field', () => {
  it('drops keys matching /secret|skey/i at any depth, recursively', () => {
    const input = {
      integration_key: 'DIXXXXXXXXXXXXXXXXXX',
      name: 'My App',
      secret_key: 'super-secret-value',
      SKEY: 'legacy-cased-secret',
      nested: { skey: 'nested-secret', ok: 'kept', deeper: { client_secret: 'also-dropped', safe: 1 } },
      list: [{ secret: 'x' }, { fine: 'y' }],
    };
    const output = stripSecretFields(input) as Record<string, unknown>;
    expect(output.integration_key).toBe('DIXXXXXXXXXXXXXXXXXX');
    expect(output.name).toBe('My App');
    expect(output.secret_key).toBeUndefined();
    expect(output.SKEY).toBeUndefined();
    const nested = output.nested as Record<string, unknown>;
    expect(nested.skey).toBeUndefined();
    expect(nested.ok).toBe('kept');
    expect((nested.deeper as Record<string, unknown>).client_secret).toBeUndefined();
    expect((nested.deeper as Record<string, unknown>).safe).toBe(1);
    const list = output.list as Array<Record<string, unknown>>;
    expect(list[0].secret).toBeUndefined();
    expect(list[1].fine).toBe('y');
  });

  it('leaves primitives and arrays of primitives untouched', () => {
    expect(stripSecretFields('hello')).toBe('hello');
    expect(stripSecretFields(42)).toBe(42);
    expect(stripSecretFields(null)).toBe(null);
    expect(stripSecretFields([1, 2, 3])).toEqual([1, 2, 3]);
  });
});
