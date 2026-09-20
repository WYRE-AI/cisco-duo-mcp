import type { Tool } from '@modelcontextprotocol/sdk/types.js';
import { AUTH_TOOLS, handleAuthTool, isAuthTool } from './auth.js';
import { GROUP_TOOLS, handleGroupTool, isGroupTool } from './groups.js';
import { handleIntegrationTool, INTEGRATION_TOOLS, isIntegrationTool } from './integrations.js';
import { handleLogTool, isLogTool, LOG_TOOLS } from './logs.js';
import { handlePhoneTool, isPhoneTool, PHONE_TOOLS } from './phones.js';
import { handleTokenTool, isTokenTool, TOKEN_TOOLS } from './tokens.js';
import { handleUserTool, isUserTool, USER_TOOLS } from './users.js';
import type { CallToolResult } from './types.js';

export const ALL_TOOLS: Tool[] = [
  ...USER_TOOLS,
  ...PHONE_TOOLS,
  ...TOKEN_TOOLS,
  ...GROUP_TOOLS,
  ...INTEGRATION_TOOLS,
  ...LOG_TOOLS,
  ...AUTH_TOOLS,
];

export async function dispatchToolCall(name: string, args: Record<string, unknown>): Promise<CallToolResult> {
  if (isUserTool(name)) return handleUserTool(name, args);
  if (isPhoneTool(name)) return handlePhoneTool(name, args);
  if (isTokenTool(name)) return handleTokenTool(name, args);
  if (isGroupTool(name)) return handleGroupTool(name, args);
  if (isIntegrationTool(name)) return handleIntegrationTool(name, args);
  if (isLogTool(name)) return handleLogTool(name, args);
  if (isAuthTool(name)) return handleAuthTool(name, args);
  return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
}
