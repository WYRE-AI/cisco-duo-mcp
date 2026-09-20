import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { createServer } from './server.js';
import { logger } from './utils/logger.js';

const server = createServer();
const transport = new StdioServerTransport();
await server.connect(transport);
logger.info('Cisco Duo MCP server started (stdio)');
