import type { DuoCredentials } from '../types.js';
import type { CallToolResult } from './types.js';

export function textResult(value: unknown): CallToolResult {
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: 'text', text }] };
}

export function errorResult(message: string): CallToolResult {
  return { content: [{ type: 'text', text: `Error: ${message}` }], isError: true };
}

/** Returns an error CallToolResult if credentials are missing, else null. */
export function requireCredentials(creds: DuoCredentials | null): CallToolResult | null {
  if (!creds) {
    return errorResult('No Duo credentials configured. Set DUO_IKEY, DUO_SKEY, and DUO_API_HOST.');
  }
  return null;
}

/** Shared input-schema fragment for Duo's offset-paginated list endpoints. */
export const PAGE_PARAMS_PROPERTIES = {
  limit: { type: 'number', description: 'Number of items per page (Duo default/max vary by endpoint).' },
  offset: { type: 'number', description: 'Offset into the result set, for paging past the first page.' },
} as const;
