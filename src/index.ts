#!/usr/bin/env node
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { loadConfig } from './config.js';
import { createServer } from './server.js';
import type { Config } from './types.js';

let config: Config;
try {
  config = loadConfig(process.env.SFTP_MCP_CONFIG);
} catch (err) {
  console.error(`sftp-mcp: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

for (const h of config.hosts.values()) {
  if (h.protocol === 'ftps' && !h.tls) console.error(`sftp-mcp: WARNING host ${h.name} uses plain FTP (unencrypted)`);
}

await createServer(config).connect(new StdioServerTransport());
