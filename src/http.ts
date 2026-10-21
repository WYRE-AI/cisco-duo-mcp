import { realpathSync } from 'node:fs';
import { createServer as createHttpServer, type Server } from 'node:http';
import { fileURLToPath } from 'node:url';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

/**
 * HTTP transport fail-closed policy (CWE-306).
 *
 * An empty or placeholder CONDUIT_S2S_SECRET used to skip X-Gateway-S2S
 * and leave /mcp open. Startup now refuses to listen unless the secret is
 * a real provisioned value. MCP_ALLOW_INSECURE_DEV=1 is the only bypass:
 * it logs a warning and binds 127.0.0.1 only, ignoring a wider MCP_HTTP_HOST.
 *
 * A configured secret keeps honoring MCP_HTTP_HOST (unset stays 0.0.0.0,
 * the historical default; the container image sets 0.0.0.0 explicitly).
 * With no usable secret the bind address is 127.0.0.1.
 *
 * The secret value is never written to logs.
 */

const LOOPBACK_HOST = '127.0.0.1';

/**
 * Values that must not count as a gateway-provisioned service-to-service
 * secret. Comparison is case-insensitive after trim. Unresolved ${...} and
 * <...> templates are rejected separately.
 */
export const KNOWN_S2S_PLACEHOLDER_VALUES = [
  'changeme',
  'change-me',
  'change_me',
  'placeholder',
  'your-s2s-secret',
  'your_s2s_secret',
  'your-secret',
  'your_secret',
  'your-secret-here',
  'replace-me',
  'replace_me',
  'replace_with_secret',
  'set-me',
  'todo',
  'xxx',
  's2s-secret',
  'password',
  'example',
  'dummy',
  '${conduit_s2s_secret}',
  '<conduit_s2s_secret>',
] as const;

const KNOWN_S2S_PLACEHOLDERS = new Set<string>(KNOWN_S2S_PLACEHOLDER_VALUES);

/** Unresolved config templates, e.g. `${CONDUIT_S2S_SECRET}` or `<secret>`. */
const UNRESOLVED_PLACEHOLDER = /^(\$\{[^}]+\}|<[^>]+>)$/;

const S2S_UNAUTHORIZED = {
  error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
};

const GATEWAY_CREDENTIALS_UNAUTHORIZED = {
  jsonrpc: '2.0',
  error: {
    code: -32001,
    message:
      'Missing credentials: X-Duo-Ikey, X-Duo-Skey, and X-Duo-Api-Host headers are required in gateway mode',
  },
  id: null,
};

export type S2sSecretClassification = {
  secret: string;
  reason: 'ok' | 'empty' | 'placeholder';
};

/** Classify CONDUIT_S2S_SECRET. Placeholder and blank values are not usable secrets. */
export function classifyS2sSecret(raw: string | undefined): S2sSecretClassification {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return { secret: '', reason: 'empty' };
  if (KNOWN_S2S_PLACEHOLDERS.has(trimmed.toLowerCase()) || UNRESOLVED_PLACEHOLDER.test(trimmed)) {
    return { secret: '', reason: 'placeholder' };
  }
  return { secret: trimmed, reason: 'ok' };
}

function headerValue(value: string | string[] | undefined): string | undefined {
  const raw = Array.isArray(value) ? value[0] : value;
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

/**
 * Fail closed. Empty and known placeholders are the same condition: do not
 * listen unless the operator explicitly opts into insecure local dev.
 * Never interpolate the secret into the log.
 */
function resolveHttpS2sSecret(): string {
  const { secret, reason } = classifyS2sSecret(process.env.CONDUIT_S2S_SECRET);
  if (secret) return secret;

  const why =
    reason === 'placeholder'
      ? 'CONDUIT_S2S_SECRET is a known placeholder value, not a provisioned service-to-service secret.'
      : 'CONDUIT_S2S_SECRET is empty.';

  if (process.env.MCP_ALLOW_INSECURE_DEV === '1') {
    logger.error(
      `SECURITY WARNING: ${why} MCP_ALLOW_INSECURE_DEV=1 is set, so the HTTP server is starting WITHOUT ` +
        'service-to-service authentication and listens on 127.0.0.1 only. ' +
        'Do not use MCP_ALLOW_INSECURE_DEV outside local development.',
    );
    return '';
  }

  logger.error(
    `Refusing to start HTTP transport: ${why} ` +
      'An empty or placeholder secret would accept unauthenticated /mcp requests (CWE-306). ' +
      'Set CONDUIT_S2S_SECRET to the gateway-provisioned service-to-service secret, ' +
      'or set MCP_ALLOW_INSECURE_DEV=1 for local development only.',
  );
  process.exit(1);
}

/**
 * No usable secret: always 127.0.0.1, even when MCP_HTTP_HOST is 0.0.0.0
 * (the image default). A configured secret honors MCP_HTTP_HOST and keeps
 * the historical 0.0.0.0 default when that variable is unset.
 */
function resolveListenHost(s2sSecret: string): string {
  const configured = (process.env.MCP_HTTP_HOST ?? '').trim();
  if (s2sSecret) return configured || '0.0.0.0';

  if (configured && configured !== LOOPBACK_HOST) {
    logger.error(
      `WARNING: MCP_HTTP_HOST=${configured} is not 127.0.0.1. ` +
        'MCP_ALLOW_INSECURE_DEV=1 without a usable CONDUIT_S2S_SECRET cannot listen there. ' +
        `Binding ${LOOPBACK_HOST} only.`,
    );
  }
  return LOOPBACK_HOST;
}

function isDirectExecution(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return realpathSync(fileURLToPath(import.meta.url)) === realpathSync(entry);
  } catch {
    return false;
  }
}

/**
 * Start the Cisco Duo MCP Streamable HTTP server.
 *
 * Fails closed: a missing, blank, or known-placeholder CONDUIT_S2S_SECRET is
 * treated as no secret, logs an error, and calls process.exit(1) before
 * anything listens. Only MCP_ALLOW_INSECURE_DEV=1 lets it start without a
 * usable secret; it then skips X-Gateway-S2S and binds 127.0.0.1 only. With a
 * secret, every /mcp request must carry a valid X-Gateway-S2S header; /health
 * stays unauthenticated. The listener speaks plain HTTP (no in-process TLS), so
 * expose it only behind a TLS-terminating trusted ingress or on a private network.
 *
 * @returns The listening `Server`, once `listen` has succeeded.
 * @throws Rejects with the bind error (for example EADDRINUSE or EACCES) if
 *   the port cannot be bound.
 */
export async function startHttpServer(): Promise<Server> {
  const s2sSecret = resolveHttpS2sSecret();
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = resolveListenHost(s2sSecret);
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    // Fixed base: a malformed Host header must not throw before auth.
    let url: URL;
    try {
      url = new URL(req.url || '/', 'http://localhost');
    } catch {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad request' }));
      return;
    }

    if (url.pathname === '/health') {
      // /health is container LIVENESS, not credential-readiness. It stays
      // unauthenticated and must not read Duo credentials or the S2S secret.
      // In gateway mode credentials arrive per request, so a credential
      // check here would not describe whether any customer is connected.
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          timestamp: new Date().toISOString(),
        }),
      );
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
      return;
    }

    // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1.
    // A configured secret is always enforced, before credential extraction.
    if (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(S2S_UNAUTHORIZED));
      return;
    }

    // node:http does not await this listener. Catch a rejected connect or
    // handleRequest so one bad request cannot crash the process. The log
    // stays generic because error text can echo tenant credentials.
    const fail = (error: unknown): void => {
      logger.error('MCP request failed', { errorName: error instanceof Error ? error.name : typeof error });
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
      if (!res.writableEnded) res.end(JSON.stringify({ error: 'Internal server error' }));
    };

    const handle = async () => {
      // SECURITY-CRITICAL invariant: this transport MUST stay stateless
      // (sessionIdGenerator: undefined + enableJsonResponse: true).
      // Per-request tenant credentials are carried in an AsyncLocalStorage
      // context opened by runWithCredentials() below. A stateless
      // request->single-response flow keeps the tool call inside that
      // context - switching to a stateful/SSE transport would let a
      // long-lived connection serve later messages under a stale/foreign
      // credential context.
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (isGatewayMode) {
      // Credentials must arrive on every request. Falling through would
      // resolve DUO_IKEY / DUO_SKEY / DUO_API_HOST from the process
      // environment, which is not request-scoped.
      const ikey = headerValue(req.headers['x-duo-ikey']);
      const skey = headerValue(req.headers['x-duo-skey']);
      const apiHost = headerValue(req.headers['x-duo-api-host']);
      if (!ikey || !skey || !apiHost) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(GATEWAY_CREDENTIALS_UNAUTHORIZED));
        return;
      }
      await runWithCredentials({ ikey, skey, apiHost }, handle).catch(fail);
      return;
    }

    await handle().catch(fail);
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (err: Error) => reject(err);
    httpServer.once('error', onError);
    httpServer.listen(port, host, () => {
      httpServer.removeListener('error', onError);
      logger.info(`HTTP streaming server listening on ${host}:${port}`, {
        s2s: s2sSecret ? 'enforced' : 'disabled',
        authMode: isGatewayMode ? 'gateway' : 'env',
      });
      resolve();
    });
  });

  return httpServer;
}

// Direct `node dist/http.js` starts the server. Importing this module
// (tests, the stdio bundle) must not listen or load the stdio entrypoint.
if (isDirectExecution()) {
  const transport = process.env.MCP_TRANSPORT;
  if (transport === 'http') {
    startHttpServer().catch((error) => {
      logger.error('Fatal startup error', {
        error: error instanceof Error ? error.message : String(error),
      });
      process.exit(1);
    });
  } else {
    import('./index.js');
  }
}
