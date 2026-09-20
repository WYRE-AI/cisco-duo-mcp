import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getPhone, listPhones } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

/**
 * Phones - READ-ONLY. Duo's Admin API has no "list users of a phone_id"
 * endpoint (verified against duo_client_python - only the reverse
 * direction, phones-of-a-user, exists; see tools/users.ts).
 */
export const PHONE_TOOLS: Tool[] = [
  {
    name: 'duo_list_phones',
    description:
      'List phones in the Duo account, optionally filtered by number/extension. Returns phone metadata (phone_id, number, platform/OS, type - PII).',
    inputSchema: {
      type: 'object',
      properties: {
        number: { type: 'string', description: 'Filter by exact phone number.' },
        extension: { type: 'string', description: 'Filter by extension.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'duo_get_phone',
    description: 'Get full detail for a single phone by phone_id.',
    inputSchema: {
      type: 'object',
      properties: { phoneId: { type: 'string', description: 'Duo phone_id.' } },
      required: ['phoneId'],
    },
  },
];

const TOOL_NAMES = new Set(PHONE_TOOLS.map((t) => t.name));
export function isPhoneTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handlePhoneTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'duo_list_phones') {
      return textResult(
        await listPhones(creds!, {
          number: args.number as string | undefined,
          extension: args.extension as string | undefined,
          limit: args.limit as number | undefined,
          offset: args.offset as number | undefined,
        })
      );
    }
    if (name === 'duo_get_phone') {
      return textResult(await getPhone(creds!, args.phoneId as string));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
