import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { getCredentials, getIntegration, listIntegrations } from '../client.js';
import type { CallToolResult } from './types.js';
import { errorResult, PAGE_PARAMS_PROPERTIES, requireCredentials, textResult } from './shared.js';

/**
 * Integrations - READ-ONLY, METADATA ONLY. Every response passes through
 * client.ts's stripSecretFields() before it reaches the model - Duo's
 * Integrations schema is not fully documented in machine-readable form
 * for every integration type, and this is a defensive measure against any
 * secret/skey-shaped field being echoed in a read response. This never
 * returns integration secret keys.
 */
export const INTEGRATION_TOOLS: Tool[] = [
  {
    name: 'duo_list_integrations',
    description:
      'List integrations configured in the Duo account (integration_key, name, type, status). Metadata only - secret keys are stripped before this tool ever returns a response.',
    inputSchema: { type: 'object', properties: { ...PAGE_PARAMS_PROPERTIES } },
  },
  {
    name: 'duo_get_integration',
    description:
      'Get full metadata for a single integration by integration_key. Metadata only - secret keys are stripped before this tool ever returns a response.',
    inputSchema: {
      type: 'object',
      properties: { integrationKey: { type: 'string', description: 'Duo integration_key.' } },
      required: ['integrationKey'],
    },
  },
];

const TOOL_NAMES = new Set(INTEGRATION_TOOLS.map((t) => t.name));
export function isIntegrationTool(name: string): boolean {
  return TOOL_NAMES.has(name);
}

export async function handleIntegrationTool(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  const creds = getCredentials();
  const missing = requireCredentials(creds);
  if (missing) return missing;

  try {
    if (name === 'duo_list_integrations') {
      return textResult(
        await listIntegrations(creds!, { limit: args.limit as number | undefined, offset: args.offset as number | undefined })
      );
    }
    if (name === 'duo_get_integration') {
      return textResult(await getIntegration(creds!, args.integrationKey as string));
    }

    return errorResult(`Unknown tool: ${name}`);
  } catch (err) {
    return errorResult((err as Error).message);
  }
}
