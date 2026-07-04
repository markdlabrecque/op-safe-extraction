import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { listVaults, listItems, searchItems, getItem } from './tools.js';

const server = new McpServer({ name: 'op-safe-extraction', version: '0.1.0' });

const json = (data: unknown) => ({ content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] });

server.tool(
  'list_vaults',
  'List all 1Password vaults visible to this integration, with whether each is allowlisted for access.',
  {},
  async () => json(await listVaults()),
);

server.tool(
  'list_items',
  'List item titles, tags, and categories in an allowlisted vault. No field values.',
  { vaultId: z.string() },
  async ({ vaultId }) => json(await listItems(vaultId)),
);

server.tool(
  'search_items',
  'Search items in an allowlisted vault by title text and/or tags.',
  { vaultId: z.string(), query: z.string().optional(), tags: z.array(z.string()).optional() },
  async ({ vaultId, query, tags }) => json(await searchItems(vaultId, query, tags)),
);

server.tool(
  'get_item',
  'Get full metadata for one item in an allowlisted vault. Sensitive field values (passwords, passkeys, SSH keys, notes) are redacted.',
  { vaultId: z.string(), itemId: z.string() },
  async ({ vaultId, itemId }) => json(await getItem(vaultId, itemId)),
);

const transport = new StdioServerTransport();
await server.connect(transport);
