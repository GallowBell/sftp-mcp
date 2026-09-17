import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import * as ftps from './ftp.js';
import { resolveLocalFile, resolveRemote, resolveRemoteFile } from './paths.js';
import * as sftp from './sftp.js';
import type { Config, HostConfig } from './types.js';

const PLAIN_FTP_WARNING = 'plain FTP: credentials and data sent unencrypted';

export function redact(text: string, secrets: string[]): string {
  return secrets.reduce((t, s) => t.split(s).join('***'), text);
}

export function createServer(config: Config): McpServer {
  const server = new McpServer({ name: 'sftp-mcp', version: '0.1.0' });

  const getHost = (name: string): HostConfig => {
    const h = config.hosts.get(name);
    if (!h) throw new Error('Unknown host');
    return h;
  };
  const insecure = (h: HostConfig) => h.protocol === 'ftps' && !h.tls;
  const withWarning = (h: HostConfig, result: object) => (insecure(h) ? { ...result, warning: PLAIN_FTP_WARNING } : result);

  const run = <A>(fn: (args: A) => Promise<unknown>) => async (args: A) => {
    try {
      return { content: [{ type: 'text' as const, text: JSON.stringify(await fn(args), null, 2) }] };
    } catch (err) {
      const e = err instanceof Error ? err : new Error(String(err));
      console.error(redact(e.stack ?? e.message, config.secrets));
      return { content: [{ type: 'text' as const, text: redact(e.message, config.secrets) }], isError: true };
    }
  };

  const hostArg = z.string().describe('Host name from list_hosts');
  const remoteArg = z.string().default('').describe('Absolute path, or relative to the host remoteRoot');

  server.registerTool(
    'list_hosts',
    { description: 'List configured upload targets (no credentials).' },
    run(async () =>
      [...config.hosts.values()].map((h) => ({
        name: h.name, protocol: h.protocol, host: h.host, port: h.port,
        remoteRoot: h.remoteRoot, allowOverwrite: h.allowOverwrite, insecure: insecure(h),
      })),
    ),
  );

  server.registerTool(
    'upload_file',
    {
      description: 'Upload a local file (inside the host localRoot) to the host (inside remoteRoot). The remote parent directory must exist.',
      inputSchema: {
        host: hostArg,
        localPath: z.string().describe('Absolute path, or relative to the host localRoot'),
        remotePath: z.string().describe('Absolute path, or relative to the host remoteRoot'),
      },
    },
    run(async ({ host, localPath, remotePath }: { host: string; localPath: string; remotePath: string }) => {
      const h = getHost(host);
      const remote = resolveRemoteFile(h.remoteRoot, remotePath);
      const local = await resolveLocalFile(h.localRoot, localPath);
      if (h.maxBytes !== undefined && local.size > h.maxBytes) {
        throw new Error(`File is ${local.size} bytes, exceeds maxBytes ${h.maxBytes}`);
      }
      const result = h.protocol === 'sftp'
        ? await sftp.upload(h, local.path, remote, local.size)
        : await ftps.upload(h, local.path, remote, local.size);
      return withWarning(h, result);
    }),
  );

  server.registerTool(
    'list_dir',
    { description: 'List a remote directory inside remoteRoot (max 1000 entries).', inputSchema: { host: hostArg, remotePath: remoteArg } },
    run(async ({ host, remotePath }: { host: string; remotePath: string }) => {
      const h = getHost(host);
      const remote = resolveRemote(h.remoteRoot, remotePath);
      const result = h.protocol === 'sftp' ? await sftp.listDir(h, remote) : await ftps.listDir(h, remote);
      return withWarning(h, result);
    }),
  );

  server.registerTool(
    'stat',
    { description: 'Check whether a remote path inside remoteRoot exists, and its type/size.', inputSchema: { host: hostArg, remotePath: remoteArg } },
    run(async ({ host, remotePath }: { host: string; remotePath: string }) => {
      const h = getHost(host);
      const remote = resolveRemote(h.remoteRoot, remotePath);
      const result = h.protocol === 'sftp' ? await sftp.stat(h, remote) : await ftps.stat(h, remote);
      return withWarning(h, result);
    }),
  );

  return server;
}
