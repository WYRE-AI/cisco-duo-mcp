/**
 * HTTP transport TLS-or-loopback policy (CWE-319).
 *
 * Non-loopback binds refuse to start unless MCP_TLS_CERT_FILE +
 * MCP_TLS_KEY_FILE (in-process HTTPS) or MCP_TRUSTED_TLS_INGRESS=1 is set.
 * The S2S fail-closed check runs first.
 */

import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import type { Server } from 'node:http';
import { Server as HttpsServer, request as httpsRequest } from 'node:https';
import type { AddressInfo } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { isLoopbackHost, startHttpServer } from '../http.js';

const S2S_SECRET = 's2s-do-not-log-7f3a';

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'MCP_TRUSTED_TLS_INGRESS',
  'MCP_TLS_CERT_FILE',
  'MCP_TLS_KEY_FILE',
  'AUTH_MODE',
  'LOG_LEVEL',
] as const;

const savedEnv = new Map<string, string | undefined>();
const servers: Server[] = [];
let logLines: string[] = [];
let tmpDir = '';
let certFile = '';
let keyFile = '';
let opensslReason = '';

function hasOpenssl(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
  tmpDir = mkdtempSync(join(tmpdir(), 'mcp-tls-'));
  certFile = join(tmpDir, 'cert.pem');
  keyFile = join(tmpDir, 'key.pem');
  if (!hasOpenssl()) {
    opensslReason = 'openssl is not available';
    return;
  }
  try {
    execFileSync(
      'openssl',
      ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost', '-days', '1', '-keyout', keyFile, '-out', certFile],
      { stdio: 'ignore' },
    );
  } catch {
    opensslReason = 'openssl could not generate a self-signed certificate';
  }
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

beforeEach(() => {
  for (const key of ENV_KEYS) delete process.env[key];
  process.env.MCP_HTTP_PORT = '0';
  process.env.LOG_LEVEL = 'info';
  process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
  logLines = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    logLines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  vi.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logLines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${String(code)}`);
  }) as typeof process.exit);
});

afterEach(async () => {
  vi.restoreAllMocks();
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server?.listening) continue;
    await new Promise<void>((resolvePromise, reject) => {
      server.close((err) => (err ? reject(err) : resolvePromise()));
    });
  }
});

async function start(): Promise<{ server: Server; port: number }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address() as AddressInfo;
  return { server, port: bound.port };
}

function logged(): string {
  return logLines.join('\n');
}

describe('isLoopbackHost', () => {
  it.each(['127.0.0.1', '127.1.2.3', '::1', '[::1]', 'localhost', 'LocalHost', ' 127.0.0.1 '])(
    'treats %s as loopback',
    (host) => {
      expect(isLoopbackHost(host)).toBe(true);
    },
  );

  it.each(['0.0.0.0', '::', '10.0.0.5', '128.0.0.1', '127.0.0.1.evil.com', '127.0.0.256', 'example.com', ''])(
    'treats %s as non-loopback',
    (host) => {
      expect(isLoopbackHost(host)).toBe(false);
    },
  );
});

describe('transport security at startup', () => {
  it('starts plain HTTP on a loopback bind with no flag and no TLS files', async () => {
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    const { server } = await start();
    expect(server).not.toBeInstanceOf(HttpsServer);
    expect(process.exit).not.toHaveBeenCalled();
    expect(logged()).not.toContain('SECURITY WARNING');
  });

  it('refuses a non-loopback bind with no TLS and no flag', async () => {
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(logged()).toContain('MCP_TRUSTED_TLS_INGRESS');
    expect(logged()).toContain('CWE-319');
    expect(logged()).not.toContain(S2S_SECRET);
    expect(servers).toHaveLength(0);
  });

  it('refuses when MCP_HTTP_HOST is unset (default 0.0.0.0)', async () => {
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(logged()).toContain('MCP_TRUSTED_TLS_INGRESS');
  });

  it('does not accept MCP_TRUSTED_TLS_INGRESS values other than 1', async () => {
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.MCP_TRUSTED_TLS_INGRESS = 'true';
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
  });

  it('starts plain HTTP behind a trusted ingress with exactly one warning', async () => {
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.MCP_TRUSTED_TLS_INGRESS = '1';
    const { server } = await start();
    expect(server).not.toBeInstanceOf(HttpsServer);
    const warnings = logLines.filter((line) => line.includes('MCP_TRUSTED_TLS_INGRESS'));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain('SECURITY WARNING');
    expect(logged()).not.toContain(S2S_SECRET);
  });

  it.each([
    ['MCP_TLS_CERT_FILE', 'MCP_TLS_KEY_FILE'],
    ['MCP_TLS_KEY_FILE', 'MCP_TLS_CERT_FILE'],
  ])('refuses when only %s is set (missing %s)', async (present, missing) => {
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env[present] = join(tmpDir, 'whatever.pem');
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(logged()).toContain(missing);
    expect(servers).toHaveLength(0);
  });

  it('refuses when a TLS file cannot be read', async () => {
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_TLS_CERT_FILE = join(tmpDir, 'missing-cert.pem');
    process.env.MCP_TLS_KEY_FILE = join(tmpDir, 'missing-key.pem');
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(logged()).toContain('ENOENT');
  });

  it('fires the S2S fail-closed error before the TLS check', async () => {
    process.env.CONDUIT_S2S_SECRET = '';
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(logged()).toContain('CONDUIT_S2S_SECRET is empty');
    expect(logged()).toContain('CWE-306');
    expect(logged()).not.toContain('CWE-319');
  });
});

describe('in-process HTTPS', () => {
  it('serves HTTPS when both TLS files are set on a non-loopback bind', async (ctx) => {
    if (opensslReason) ctx.skip();
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.MCP_TLS_CERT_FILE = certFile;
    process.env.MCP_TLS_KEY_FILE = keyFile;
    const { server, port } = await start();
    expect(server).toBeInstanceOf(HttpsServer);
    expect(logged()).toContain('TLS enabled');
    expect(logged()).not.toContain('SECURITY WARNING');

    const status = await new Promise<number>((resolvePromise, reject) => {
      const req = httpsRequest(
        { hostname: '127.0.0.1', port, path: '/health', method: 'GET', rejectUnauthorized: false },
        (res) => {
          res.resume();
          res.on('end', () => resolvePromise(res.statusCode ?? 0));
        },
      );
      req.setTimeout(5000, () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.end();
    });
    expect(status).toBe(200);

    await expect(
      new Promise<number>((resolvePromise, reject) => {
        const req = httpRequest({ hostname: '127.0.0.1', port, path: '/health', method: 'GET' }, (res) => {
          res.resume();
          res.on('end', () => resolvePromise(res.statusCode ?? 0));
        });
        req.setTimeout(5000, () => req.destroy(new Error('timeout')));
        req.on('error', reject);
        req.end();
      }),
    ).rejects.toBeDefined();
  });

  it('also serves HTTPS on a loopback bind when both TLS files are set', async (ctx) => {
    if (opensslReason) ctx.skip();
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_TLS_CERT_FILE = certFile;
    process.env.MCP_TLS_KEY_FILE = keyFile;
    const { server } = await start();
    expect(server).toBeInstanceOf(HttpsServer);
  });
});

