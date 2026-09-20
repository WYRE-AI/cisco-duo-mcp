import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import {
  getCredentials,
  getUser,
  listUserGroups,
  listUserPhones,
  listUsers,
  listUserTokens,
  listUserU2fTokens,
  listUserWebauthnCredentials,
} from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

/**
 * Users - READ-ONLY. Lists/details a user and the MFA methods enrolled to
 * them (groups, phones, hardware tokens, WebAuthn credentials, U2F
 * tokens). No bypass-code tool exists here - Duo's bypass-code endpoints
 * (both the GET that returns live codes and the POST that generates them)
 * are hard-excluded by design. See README's Scope section.
 */
export const USER_TOOLS: Tool[] = [
  {
    name: 'duo_list_users',
    description:
      'List users in the Duo account, optionally filtered by exact username. Returns user metadata (user_id, username, email, status, realname, phone/created timestamps) - PII, classified isAdmin.',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string', description: 'Filter by exact username match.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'duo_get_user',
    description: 'Get full detail for a single user by user_id, including status and enrolled-factor summary.',
    inputSchema: {
      type: 'object',
      properties: { userId: { type: 'string', description: 'Duo user_id.' } },
      required: ['userId'],
    },
  },
  {
    name: 'duo_list_user_groups',
    description: "List the groups a user belongs to.",
    inputSchema: {
      type: 'object',
      properties: { userId: { type: 'string', description: 'Duo user_id.' }, ...PAGE_PARAMS_PROPERTIES },
      required: ['userId'],
    },
  },
  {
    name: 'duo_list_user_phones',
    description: "List the phones enrolled to a user (number, platform/OS, capabilities - PII).",
    inputSchema: {
      type: 'object',
      properties: { userId: { type: 'string', description: 'Duo user_id.' }, ...PAGE_PARAMS_PROPERTIES },
      required: ['userId'],
    },
  },
  {
    name: 'duo_list_user_tokens',
    description: "List the hardware tokens enrolled to a user (type, serial - never the token's secret seed, which is stripped).",
    inputSchema: {
      type: 'object',
      properties: { userId: { type: 'string', description: 'Duo user_id.' }, ...PAGE_PARAMS_PROPERTIES },
      required: ['userId'],
    },
  },
  {
    name: 'duo_list_user_webauthn_credentials',
    description: "List the WebAuthn credentials (security keys, platform authenticators) enrolled to a user. Never returns private key material.",
    inputSchema: {
      type: 'object',
      properties: { userId: { type: 'string', description: 'Duo user_id.' }, ...PAGE_PARAMS_PROPERTIES },
      required: ['userId'],
    },
  },
  {
    name: 'duo_list_user_u2f_tokens',
    description: "List the legacy U2F security keys enrolled to a user. Never returns private key material.",
    inputSchema: {
      type: 'object',
      properties: { userId: { type: 'string', description: 'Duo user_id.' }, ...PAGE_PARAMS_PROPERTIES },
      required: ['userId'],
    },
  },
];

const TOOL_NAMES = new Set(USER_TOOLS.map((t) => t.name));
export function isUserTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleUserTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    const userId = args.userId as string;
    const page = { limit: args.limit as number | undefined, offset: args.offset as number | undefined };

    if (name === 'duo_list_users') {
      return textResult(await listUsers(creds!, { username: args.username as string | undefined, ...page }));
    }
    if (name === 'duo_get_user') {
      return textResult(await getUser(creds!, userId));
    }
    if (name === 'duo_list_user_groups') {
      return textResult(await listUserGroups(creds!, userId, page));
    }
    if (name === 'duo_list_user_phones') {
      return textResult(await listUserPhones(creds!, userId, page));
    }
    if (name === 'duo_list_user_tokens') {
      return textResult(await listUserTokens(creds!, userId, page));
    }
    if (name === 'duo_list_user_webauthn_credentials') {
      return textResult(await listUserWebauthnCredentials(creds!, userId, page));
    }
    if (name === 'duo_list_user_u2f_tokens') {
      return textResult(await listUserU2fTokens(creds!, userId, page));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
