import { createServer as createHttpServer, type Server as HttpServer } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { getCredentials, runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import { MAX_REQUEST_BODY_BYTES } from './input-limits.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

export async function startHttpServer(): Promise<HttpServer> {
  const S2S_SECRET = process.env.CONDUIT_S2S_SECRET || '';
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = process.env.MCP_HTTP_HOST || '0.0.0.0';
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    if (url.pathname === '/health') {
      // /health is container LIVENESS, not credential-readiness. In gateway
      // mode, credentials arrive per-request via X-Duo-Ikey/X-Duo-Skey/
      // X-Duo-Api-Host, not at startup - checking getCredentials() here
      // would 503 the container permanently regardless of whether any
      // customer has connected yet.
      const creds = getCredentials();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          credentials: { configured: !!creds },
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
      return;
    }

    if (S2S_SECRET && !verifyS2sHeader(req.headers[S2S_HEADER] as string | undefined, S2S_SECRET)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
        })
      );
      return;
    }

    // Body cap runs only after S2S passes so unauthenticated callers still get 401.
    const contentLength = Number(req.headers['content-length']);
    if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BODY_BYTES) {
      res.writeHead(413, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          jsonrpc: '2.0',
          error: { code: -32600, message: `Request body exceeds ${MAX_REQUEST_BODY_BYTES} bytes` },
          id: null,
        })
      );
      return;
    }

    const ikey = isGatewayMode ? (req.headers['x-duo-ikey'] as string | undefined) : undefined;
    const skey = isGatewayMode ? (req.headers['x-duo-skey'] as string | undefined) : undefined;
    const apiHost = isGatewayMode ? (req.headers['x-duo-api-host'] as string | undefined) : undefined;

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
        maxRequestBodySize: MAX_REQUEST_BODY_BYTES,
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (ikey && skey && apiHost) {
      await runWithCredentials({ ikey, skey, apiHost }, handle);
    } else {
      await handle();
    }
  });

  await new Promise<void>((resolve, reject) => {
    httpServer.once('error', reject);
    httpServer.listen(port, host, () => {
      logger.info(`HTTP streaming server listening on ${host}:${port}`);
      resolve();
    });
  });
  return httpServer;
}

// Entry point. Vitest imports this module to call startHttpServer, so skip
// the CLI entrypoint there. `node dist/http.js` still starts HTTP or stdio.
if (process.env.VITEST !== 'true') {
  if (process.env.MCP_TRANSPORT === 'http') {
    startHttpServer().catch((error) => {
      logger.error('Fatal startup error', { error: (error as Error).message });
      process.exit(1);
    });
  } else {
    await import('./index.js');
  }
}
