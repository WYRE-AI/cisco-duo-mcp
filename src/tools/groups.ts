import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getGroup, listGroups, listGroupUsers } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

export const GROUP_TOOLS: Tool[] = [
  {
    name: 'duo_list_groups',
    description: 'List groups in the Duo account (group_id, name, description, status).',
    inputSchema: { type: 'object', properties: { ...PAGE_PARAMS_PROPERTIES } },
  },
  {
    name: 'duo_get_group',
    description: 'Get full detail for a single group by group_id.',
    inputSchema: {
      type: 'object',
      properties: { groupId: { type: 'string', description: 'Duo group_id.' } },
      required: ['groupId'],
    },
  },
  {
    name: 'duo_list_group_users',
    description: 'List the users belonging to a group.',
    inputSchema: {
      type: 'object',
      properties: { groupId: { type: 'string', description: 'Duo group_id.' }, ...PAGE_PARAMS_PROPERTIES },
      required: ['groupId'],
    },
  },
];

const TOOL_NAMES = new Set(GROUP_TOOLS.map((t) => t.name));
export function isGroupTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleGroupTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    const page = { limit: args.limit as number | undefined, offset: args.offset as number | undefined };

    if (name === 'duo_list_groups') {
      return textResult(await listGroups(creds!, page));
    }
    if (name === 'duo_get_group') {
      return textResult(await getGroup(creds!, args.groupId as string));
    }
    if (name === 'duo_list_group_users') {
      return textResult(await listGroupUsers(creds!, args.groupId as string, page));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
