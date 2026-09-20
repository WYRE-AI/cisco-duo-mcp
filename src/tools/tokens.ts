import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getDesktopToken, getHardwareToken, listDesktopTokens, listHardwareTokens } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

/**
 * Tokens - READ-ONLY. Covers both hardware tokens (HOTP/TOTP/YubiKey,
 * `/admin/v1/tokens` - note: NOT `/hardware_tokens`, which does not exist)
 * and Duo Desktop tokens (`/admin/v1/desktoptokens`). A token's secret
 * seed is never returned by Duo's read endpoints, and the client-side
 * stripSecretFields() safety net applies to every response regardless.
 * Duo's Admin API has no "list users of a token_id" endpoint (verified
 * against duo_client_python).
 */
export const TOKEN_TOOLS: Tool[] = [
  {
    name: 'duo_list_hardware_tokens',
    description:
      'List hardware tokens (HOTP/TOTP/YubiKey) in the Duo account, optionally filtered by type/serial. Never returns a seed/secret.',
    inputSchema: {
      type: 'object',
      properties: {
        type: { type: 'string', description: 'Filter by token type.' },
        serial: { type: 'string', description: 'Filter by serial number.' },
        ...PAGE_PARAMS_PROPERTIES,
      },
    },
  },
  {
    name: 'duo_get_hardware_token',
    description: 'Get full detail for a single hardware token by token_id.',
    inputSchema: {
      type: 'object',
      properties: { tokenId: { type: 'string', description: 'Duo hardware token_id.' } },
      required: ['tokenId'],
    },
  },
  {
    name: 'duo_list_desktop_tokens',
    description: 'List Duo Desktop tokens (platform, name, status).',
    inputSchema: { type: 'object', properties: { ...PAGE_PARAMS_PROPERTIES } },
  },
  {
    name: 'duo_get_desktop_token',
    description: 'Get full detail for a single Duo Desktop token by desktoptoken_id.',
    inputSchema: {
      type: 'object',
      properties: { desktoptokenId: { type: 'string', description: 'Duo desktoptoken_id.' } },
      required: ['desktoptokenId'],
    },
  },
];

const TOOL_NAMES = new Set(TOKEN_TOOLS.map((t) => t.name));
export function isTokenTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleTokenTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'duo_list_hardware_tokens') {
      return textResult(
        await listHardwareTokens(creds!, {
          type: args.type as string | undefined,
          serial: args.serial as string | undefined,
          limit: args.limit as number | undefined,
          offset: args.offset as number | undefined,
        })
      );
    }
    if (name === 'duo_get_hardware_token') {
      return textResult(await getHardwareToken(creds!, args.tokenId as string));
    }
    if (name === 'duo_list_desktop_tokens') {
      return textResult(
        await listDesktopTokens(creds!, { limit: args.limit as number | undefined, offset: args.offset as number | undefined })
      );
    }
    if (name === 'duo_get_desktop_token') {
      return textResult(await getDesktopToken(creds!, args.desktoptokenId as string));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
