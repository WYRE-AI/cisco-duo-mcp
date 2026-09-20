import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getAdministratorLog, getAuthenticationLog, getCredentials, getTelephonyLog } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, requireCredentials, textResult } from './shared.js';

export const LOG_TOOLS: Tool[] = [
  {
    name: 'duo_get_authentication_log',
    description:
      'Get the authentication log (v2) - every MFA authentication event, filterable by time range. mintime/maxtime are Unix epoch milliseconds. Paginate with next_offset (pass back the comma-joined pair from the previous response\'s metadata.next_offset).',
    inputSchema: {
      type: 'object',
      properties: {
        mintime: { type: 'number', description: 'Only return events at or after this Unix epoch millisecond timestamp. Required.' },
        maxtime: { type: 'number', description: 'Only return events at or before this Unix epoch millisecond timestamp.' },
        limit: { type: 'number', description: 'Max results per page (Duo default 100, max 1000).' },
        next_offset: { type: 'string', description: 'Pagination cursor from a previous response.' },
        sort: { type: 'string', enum: ['asc', 'desc'], description: 'Sort order by timestamp.' },
      },
      required: ['mintime'],
    },
  },
  {
    name: 'duo_get_administrator_log',
    description: 'Get the administrator log (v1) - actions taken by Duo administrators in this account.',
    inputSchema: {
      type: 'object',
      properties: {
        mintime: { type: 'number', description: 'Only return events at or after this Unix epoch second timestamp.' },
      },
    },
  },
  {
    name: 'duo_get_telephony_log',
    description:
      'Get the telephony log (v2) - phone call/SMS credit usage events. Paginate with next_offset (pass back the comma-joined pair from the previous response\'s metadata.next_offset).',
    inputSchema: {
      type: 'object',
      properties: {
        mintime: { type: 'number', description: 'Only return events at or after this Unix epoch millisecond timestamp.' },
        maxtime: { type: 'number', description: 'Only return events at or before this Unix epoch millisecond timestamp.' },
        limit: { type: 'number', description: 'Max results per page.' },
        next_offset: { type: 'string', description: 'Pagination cursor from a previous response.' },
      },
    },
  },
];

const TOOL_NAMES = new Set(LOG_TOOLS.map((t) => t.name));
export function isLogTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleLogTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'duo_get_authentication_log') {
      return textResult(
        await getAuthenticationLog(creds!, {
          mintime: args.mintime as number,
          maxtime: args.maxtime as number | undefined,
          limit: args.limit as number | undefined,
          next_offset: args.next_offset as string | undefined,
          sort: args.sort as 'asc' | 'desc' | undefined,
        })
      );
    }
    if (name === 'duo_get_administrator_log') {
      return textResult(await getAdministratorLog(creds!, { mintime: args.mintime as number | undefined }));
    }
    if (name === 'duo_get_telephony_log') {
      return textResult(
        await getTelephonyLog(creds!, {
          mintime: args.mintime as number | undefined,
          maxtime: args.maxtime as number | undefined,
          limit: args.limit as number | undefined,
          next_offset: args.next_offset as string | undefined,
        })
      );
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
