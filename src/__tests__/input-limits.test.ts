/**
 * Request / tool-input limits (CVE-2026-111768 / GHSA-46jr-4wx8-v453,
 * GHSA-f897-62hf-6gxq; WYREAI-454).
 */

import { createHmac } from 'node:crypto';
import { request as httpRequest, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as tools from '../tools/index.js';
import { startHttpServer } from '../http.js';
import {
  MAX_REQUEST_BODY_BYTES,
  MAX_TOOL_INPUT_ELEMENTS,
  countToolInputElements,
  toolInputTooLarge,
  toolInputTooLargeResult,
} from '../input-limits.js';

describe('countToolInputElements', () => {
  it('counts nested arrays and object keys at every depth', () => {
    expect(countToolInputElements({}, 100)).toBe(0);
    expect(countToolInputElements('x', 100)).toBe(0);
    expect(countToolInputElements({ a: 1, b: [1, 2, 3] }, 100)).toBe(5);
    expect(countToolInputElements({ a: { b: { c: [1, { d: 1 }] } } }, 100)).toBe(6);
    expect(countToolInputElements([[1, 2], [3, [4]]], 100)).toBe(7);
  });

  it('exits early once the count exceeds max', () => {
    const big = new Array(1_000_000).fill(0);
    expect(countToolInputElements(big, 10)).toBeGreaterThan(10);
    const nested = Array.from({ length: 1000 }, () => new Array(1000).fill(0));
    // Stops after the outer array; never walks the 1,000 inner arrays.
    expect(countToolInputElements(nested, 10)).toBe(1000);
    expect(countToolInputElements(new Array(11).fill(0), 10)).toBe(11);
  });

  it('does not recurse (very deep nesting does not overflow the stack)', () => {
    let deep: unknown = [];
    for (let i = 0; i < 200_000; i++) deep = [deep];
    expect(countToolInputElements(deep, 1_000_000)).toBe(200_000);
  });

  it('allows exactly the limit and rejects one over', () => {
    expect(toolInputTooLarge(new Array(MAX_TOOL_INPUT_ELEMENTS).fill(0))).toBe(false);
    expect(toolInputTooLarge(new Array(MAX_TOOL_INPUT_ELEMENTS + 1).fill(0))).toBe(true);
    expect(toolInputTooLarge(undefined)).toBe(false);
  });

  it('builds the McpServer-compatible error result', () => {
    expect(toolInputTooLargeResult('t')).toEqual({
      content: [
        { type: 'text', text: 'Invalid arguments for tool t: arguments contain more than the maximum of 10000 elements' },
      ],
      isError: true,
    });
  });
});

const S2S_SECRET = 'limits-test-secret-91ac';
const servers: Server[] = [];

function s2s(): string {
  const message = `t=${Math.floor(Date.now() / 1000)}`;
  return `${message},v1=${createHmac('sha256', S2S_SECRET).update(message).digest('hex')}`;
}

function post(port: number, headers: Record<string, string>, body: string) {
  return new Promise<{ status: number; body: string }>((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: '127.0.0.1',
        port,
        method: 'POST',
        path: '/mcp',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          'content-length': String(Buffer.byteLength(body)),
          ...headers,
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
      },
    );
    req.setTimeout(5000, () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end(body);
  });
}

async function listen(): Promise<number> {
  const server = await startHttpServer();
  servers.push(server);
  return (server.address() as AddressInfo).port;
}

const OVERSIZED = JSON.stringify({ pad: 'a'.repeat(MAX_REQUEST_BODY_BYTES + 1) });

describe('HTTP request limits', () => {
  beforeEach(() => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    process.env.MCP_HTTP_PORT = '0';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.AUTH_MODE = 'env';
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    while (servers.length) {
      const s = servers.pop()!;
      await new Promise<void>((r) => s.close(() => r()));
    }
  });

  it('returns 413 with a JSON-RPC error for an oversized body with valid S2S', async () => {
    const port = await listen();
    const res = await post(port, { 'x-gateway-s2s': s2s() }, OVERSIZED);
    expect(res.status).toBe(413);
    expect(JSON.parse(res.body)).toEqual({
      jsonrpc: '2.0',
      error: { code: -32600, message: 'Request body exceeds 262144 bytes' },
      id: null,
    });
  });

  it('still returns 401 for oversized bodies with missing or invalid S2S', async () => {
    const port = await listen();
    const missing = await post(port, {}, OVERSIZED);
    const invalid = await post(port, { 'x-gateway-s2s': 't=1,v1=deadbeef' }, OVERSIZED);
    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
  });

  it('serves a normal initialize and tools/list', async () => {
    const port = await listen();
    const init = await post(
      port,
      { 'x-gateway-s2s': s2s() },
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } },
      }),
    );
    expect(init.status).toBe(200);
    const list = await post(
      port,
      { 'x-gateway-s2s': s2s() },
      JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
    );
    expect(list.status).toBe(200);
    expect(JSON.parse(list.body).result.tools.length).toBeGreaterThan(0);
  });

  it('rejects tools/call with >10000 argument elements without dispatching', async () => {
    const dispatch = vi.spyOn(tools, 'dispatchToolCall');
    const port = await listen();
    const args = { filter: { ids: new Array(MAX_TOOL_INPUT_ELEMENTS).fill(1) } };
    const res = await post(
      port,
      { 'x-gateway-s2s': s2s() },
      JSON.stringify({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'duo_list_users', arguments: args } }),
    );
    expect(res.status).toBe(200);
    const result = JSON.parse(res.body).result;
    expect(result.isError).toBe(true);
    expect(result.content[0].text).toContain('maximum of 10000 elements');
    expect(dispatch).not.toHaveBeenCalled();
  });
});
