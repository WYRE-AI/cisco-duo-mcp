/**
 * HTTP transport fail-closed auth (CWE-306).
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1.
 * Known placeholders are treated as unset. The insecure-dev bypass binds
 * 127.0.0.1 only. /mcp rejects a missing or invalid X-Gateway-S2S header.
 * AUTH_MODE=gateway rejects requests that omit X-Duo-* credential headers
 * and must not fall back to DUO_* in process.env.
 */

import { createHmac } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { request as httpRequest } from 'node:http';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const runWithCredentialsMock = vi.hoisted(() => vi.fn());
const getCredentialsMock = vi.hoisted(() => vi.fn());

vi.mock('../client.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../client.js')>();
  runWithCredentialsMock.mockImplementation(actual.runWithCredentials);
  getCredentialsMock.mockImplementation(actual.getCredentials);
  return {
    ...actual,
    runWithCredentials: (...args: Parameters<typeof actual.runWithCredentials>) => runWithCredentialsMock(...args),
    getCredentials: () => getCredentialsMock(),
  };
});

import { classifyS2sSecret, KNOWN_S2S_PLACEHOLDER_VALUES, startHttpServer } from '../http.js';

const S2S_SECRET = 's2s-do-not-log-7f3a';
const ENV_IKEY = 'env-ikey-must-not-be-used';
const ENV_SKEY = 'env-skey-must-not-be-used';
const ENV_API_HOST = 'env-host.duosecurity.com';
const HEADER_SKEY = 'header-skey-do-not-log';

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'AUTH_MODE',
  'DUO_IKEY',
  'DUO_SKEY',
  'DUO_API_HOST',
  'LOG_LEVEL',
  'MCP_TRANSPORT',
] as const;

const savedEnv = new Map<string, string | undefined>();
const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

interface HttpResult {
  status: number;
  body: string;
}

function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolvePromise, reject) => {
    const req = httpRequest(
      {
        hostname: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolvePromise({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`timeout ${options.method} ${options.path}`));
    });
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

const servers: Server[] = [];
let errorLines: string[] = [];

async function listen(): Promise<{ port: number; address: string; close: () => Promise<void> }> {
  const server = await startHttpServer();
  servers.push(server);
  const bound = server.address() as AddressInfo | null;
  if (!bound || typeof bound === 'string') {
    throw new Error('HTTP server did not bind a TCP port');
  }
  return {
    port: bound.port,
    address: bound.address,
    close: () =>
      new Promise((resolvePromise, reject) => {
        server.close((err) => (err ? reject(err) : resolvePromise()));
      }),
  };
}

function mcpHeaders(extra?: Record<string, string>): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

const listTools = JSON.stringify({
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/list',
  params: {},
});

function loggedText(): string {
  return errorLines.join('\n');
}

function assertNoSecrets(text: string): void {
  expect(text).not.toContain(S2S_SECRET);
  expect(text).not.toContain(ENV_SKEY);
  expect(text).not.toContain(HEADER_SKEY);
  expect(text).not.toContain(ENV_IKEY);
}

beforeAll(() => {
  for (const key of ENV_KEYS) savedEnv.set(key, process.env[key]);
});

afterAll(() => {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

beforeEach(() => {
  process.env.MCP_HTTP_PORT = '0';
  process.env.LOG_LEVEL = 'error';
  delete process.env.CONDUIT_S2S_SECRET;
  delete process.env.MCP_ALLOW_INSECURE_DEV;
  delete process.env.MCP_HTTP_HOST;
  delete process.env.AUTH_MODE;
  delete process.env.DUO_IKEY;
  delete process.env.DUO_SKEY;
  delete process.env.DUO_API_HOST;
  delete process.env.MCP_TRANSPORT;
  errorLines = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errorLines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  runWithCredentialsMock.mockClear();
  getCredentialsMock.mockClear();
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

describe('classifyS2sSecret', () => {
  it.each(KNOWN_S2S_PLACEHOLDER_VALUES)('rejects known placeholder %s', (value) => {
    expect(classifyS2sSecret(value)).toEqual({ secret: '', reason: 'placeholder' });
    expect(classifyS2sSecret(`  ${value.toUpperCase()}  `)).toEqual({ secret: '', reason: 'placeholder' });
  });

  it('rejects unresolved templates that are not in the fixed list', () => {
    expect(classifyS2sSecret('${DUO_SKEY}').reason).toBe('placeholder');
    expect(classifyS2sSecret('<secret>').reason).toBe('placeholder');
  });

  it('treats blank values as empty and keeps a real secret verbatim', () => {
    expect(classifyS2sSecret(undefined)).toEqual({ secret: '', reason: 'empty' });
    expect(classifyS2sSecret('   ')).toEqual({ secret: '', reason: 'empty' });
    expect(classifyS2sSecret('  AbCdef123  ')).toEqual({ secret: 'AbCdef123', reason: 'ok' });
    expect(classifyS2sSecret('not-a-placeholder-9f3a').reason).toBe('ok');
  });
});

describe('HTTP startup', () => {
  it('refuses to start when CONDUIT_S2S_SECRET is empty', async () => {
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    const text = loggedText();
    expect(text).toContain('Refusing to start HTTP transport');
    expect(text).toContain('CONDUIT_S2S_SECRET is empty');
    expect(text).toContain('CWE-306');
    assertNoSecrets(text);
  });

  it('refuses a known placeholder and does not log the value', async () => {
    process.env.CONDUIT_S2S_SECRET = 'your-s2s-secret';
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    const text = loggedText();
    expect(text).toContain('Refusing to start HTTP transport');
    expect(text).toContain('known placeholder');
    expect(text).not.toContain('your-s2s-secret');
  });

  it('still refuses when MCP_ALLOW_INSECURE_DEV is not exactly 1', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(loggedText()).toContain('Refusing to start HTTP transport');
  });

  it('allows startup with a warning and binds 127.0.0.1 when MCP_ALLOW_INSECURE_DEV=1', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    const server = await listen();
    expect(process.exit).not.toHaveBeenCalled();
    expect(server.address).toBe('127.0.0.1');
    const text = loggedText();
    expect(text).toContain('SECURITY WARNING');
    expect(text).toContain('CONDUIT_S2S_SECRET is empty');
    expect(text).toContain('MCP_ALLOW_INSECURE_DEV=1');
    expect(text).toContain('127.0.0.1');
    assertNoSecrets(text);
  });

  it('forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is public', async () => {
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.CONDUIT_S2S_SECRET = 'changeme';
    const server = await listen();
    expect(server.address).toBe('127.0.0.1');
    const text = loggedText();
    expect(text).toContain('MCP_HTTP_HOST=0.0.0.0 is not 127.0.0.1');
    expect(text).toContain('Binding 127.0.0.1 only');
    expect(text).toContain('known placeholder');
    expect(text).not.toContain('changeme');
  });

  it('honors MCP_HTTP_HOST when a real secret is set', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    const server = await listen();
    expect(server.address).toBe('0.0.0.0');
    expect(loggedText()).not.toContain('not 127.0.0.1');
    assertNoSecrets(loggedText());
  });

  it('keeps the historical 0.0.0.0 default when a secret is set and MCP_HTTP_HOST is unset', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    const server = await listen();
    expect(server.address).toBe('0.0.0.0');
  });

  it('honors an explicit loopback MCP_HTTP_HOST when a secret is set', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    const server = await listen();
    expect(server.address).toBe('127.0.0.1');
  });
});

describe('HTTP /mcp authentication', () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.AUTH_MODE = 'gateway';
    process.env.DUO_IKEY = ENV_IKEY;
    process.env.DUO_SKEY = ENV_SKEY;
    process.env.DUO_API_HOST = ENV_API_HOST;
  });

  it('returns 401 when the S2S header is missing or invalid and does not log the secret', async () => {
    const server = await listen();
    const credentialHeaders = {
      'x-duo-ikey': 'header-ikey',
      'x-duo-skey': HEADER_SKEY,
      'x-duo-api-host': 'api-header.duosecurity.com',
    };

    const missing = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders(credentialHeaders),
      body: listTools,
    });
    const invalid = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({ ...credentialHeaders, 'x-gateway-s2s': mintS2sHeader('wrong-secret') }),
      body: listTools,
    });

    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
    expect(missing.body).toContain('X-Gateway-S2S');
    expect(invalid.body).toContain('X-Gateway-S2S');
    expect(missing.body).not.toContain('Missing credentials');
    assertNoSecrets(missing.body);
    assertNoSecrets(invalid.body);
    assertNoSecrets(loggedText());
    expect(getCredentialsMock).not.toHaveBeenCalled();
    expect(runWithCredentialsMock).not.toHaveBeenCalled();
  });

  it('returns 401 in gateway mode without credential headers and does not use env credentials', async () => {
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({ 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) }),
      body: listTools,
    });

    expect(response.status).toBe(401);
    expect(response.body).toContain('Missing credentials');
    expect(response.body).toContain('X-Duo-Ikey');
    expect(response.body).toContain('X-Duo-Skey');
    expect(response.body).toContain('X-Duo-Api-Host');
    assertNoSecrets(response.body);
    expect(response.body).not.toContain(ENV_API_HOST);
    expect(getCredentialsMock).not.toHaveBeenCalled();
    expect(runWithCredentialsMock).not.toHaveBeenCalled();

    const partial = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
        'x-duo-ikey': 'header-ikey',
        'x-duo-skey': '   ',
        'x-duo-api-host': 'api-header.duosecurity.com',
      }),
      body: listTools,
    });
    expect(partial.status).toBe(401);
    expect(runWithCredentialsMock).not.toHaveBeenCalled();
  });

  it('accepts a valid S2S header plus credential headers and uses those credentials', async () => {
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders({
        'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
        'x-duo-ikey': 'header-ikey',
        'x-duo-skey': HEADER_SKEY,
        'x-duo-api-host': 'api-header.duosecurity.com',
      }),
      body: listTools,
    });

    expect(response.status).toBe(200);
    expect(response.body).toContain('duo_list_users');
    assertNoSecrets(response.body);
    assertNoSecrets(loggedText());
    expect(getCredentialsMock).not.toHaveBeenCalled();
    expect(runWithCredentialsMock).toHaveBeenCalledWith(
      { ikey: 'header-ikey', skey: HEADER_SKEY, apiHost: 'api-header.duosecurity.com' },
      expect.any(Function),
    );
  });

  it('serves /health without authentication and without reading credentials', async () => {
    const server = await listen();
    const response = await sendHttp({
      port: server.port,
      method: 'GET',
      path: '/health',
    });
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body) as { status?: string; mode?: string };
    expect(body.status).toBe('ok');
    expect(body.mode).toBe('gateway');
    assertNoSecrets(response.body);
    expect(response.body).not.toContain(ENV_API_HOST);
    expect(getCredentialsMock).not.toHaveBeenCalled();
    expect(runWithCredentialsMock).not.toHaveBeenCalled();
  });

  it('does not enforce a placeholder secret when the dev bypass is on', async () => {
    process.env.CONDUIT_S2S_SECRET = 'changeme';
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.AUTH_MODE = 'env';
    const server = await listen();
    expect(server.address).toBe('127.0.0.1');
    const response = await sendHttp({
      port: server.port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders(),
      body: listTools,
    });
    expect(response.status).toBe(200);
    expect(response.body).toContain('duo_list_users');
    expect(runWithCredentialsMock).not.toHaveBeenCalled();
  });
});

describe('deploy config', () => {
  it('leaves CONDUIT_S2S_SECRET empty in .env.example', () => {
    const example = readFileSync(resolve(repoRoot, '.env.example'), 'utf8');
    const line = example.split('\n').find((entry) => entry.startsWith('CONDUIT_S2S_SECRET='));
    expect(line).toBe('CONDUIT_S2S_SECRET=');
  });

  it('requires the secret in compose and gives the gateway service no static creds', () => {
    const compose = readFileSync(resolve(repoRoot, 'docker-compose.yml'), 'utf8');
    expect(compose).toContain('CONDUIT_S2S_SECRET=${CONDUIT_S2S_SECRET:?set CONDUIT_S2S_SECRET}');
    expect(compose).toContain('127.0.0.1:8080:8080');
    expect(compose).toContain('AUTH_MODE=gateway');
    expect(compose).not.toContain('DUO_IKEY');
    expect(compose).not.toContain('DUO_SKEY');
    expect(compose).not.toContain('DUO_API_HOST');
    expect(compose).not.toContain('env_file');
  });

  it('documents X-Gateway-S2S HMAC signing', () => {
    const readme = readFileSync(resolve(repoRoot, 'README.md'), 'utf8');
    expect(readme).toContain('X-Gateway-S2S');
    expect(readme).toContain('HMAC-SHA256');
    expect(readme).toContain('t=<unix seconds>,v1=<hex>');
    expect(readme).toContain('MCP_ALLOW_INSECURE_DEV');
  });
});
