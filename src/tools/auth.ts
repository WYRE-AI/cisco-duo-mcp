import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { checkCredentials, getCredentials } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, requireCredentials, textResult } from './shared.js';

/**
 * Auth API - a single, side-effect-free credential/connectivity check
 * (GET /auth/v2/check, same v5 signing scheme as the Admin API, same
 * per-account API host). Duo's `/auth/v2/ping` (unauthenticated liveness)
 * and `/auth/v2/auth_status` (a poll for a live `/auth` transaction) are
 * deliberately not implemented - `auth_status` has no standalone utility
 * without the `/auth`/`/preauth` MFA-initiating endpoints this connector
 * excludes by design, and `ping` returns no admin-relevant data. See
 * README's Scope section.
 */
export const AUTH_TOOLS: Tool[] = [
  {
    name: 'duo_check_credentials',
    description:
      'Validate that the configured Duo credentials (ikey/skey/api host) are correct and the Auth API is reachable. Side-effect-free - does not initiate any MFA transaction.',
    inputSchema: { type: 'object', properties: {} },
  },
];

const TOOL_NAMES = new Set(AUTH_TOOLS.map((t) => t.name));
export function isAuthTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleAuthTool(name: string, _args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'duo_check_credentials') {
      return textResult(await checkCredentials(creds!));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
