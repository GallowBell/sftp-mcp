import { readFileSync, realpathSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import path from 'node:path';
import { z } from 'zod';
import { normalizeRemoteRoot } from './paths.js';
import type { Config, HostConfig, SftpAuth } from './types.js';

const HOST_NAME = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const envName = z.string().min(1);

const common = {
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1),
  remoteRoot: z.string().min(1),
  localRoot: z.string().min(1),
  allowOverwrite: z.boolean().optional(),
  maxBytes: z.number().int().positive().optional(),
  connectTimeoutMs: z.number().int().positive().optional(),
};

const hostSchema = z.discriminatedUnion('protocol', [
  z.strictObject({
    protocol: z.literal('sftp'),
    ...common,
    auth: z.discriminatedUnion('type', [
      z.strictObject({ type: z.literal('password'), passwordEnv: envName }),
      z.strictObject({ type: z.literal('key'), keyPath: z.string().min(1), passphraseEnv: envName.optional() }),
      z.strictObject({ type: z.literal('agent'), agentSocket: z.string().min(1).optional() }),
    ]),
    hostKeySha256: z.array(z.string().regex(/^SHA256:[A-Za-z0-9+/]{43}$/)).min(1).optional(),
    knownHostsPath: z.string().min(1).optional(),
  }),
  z.strictObject({
    protocol: z.literal('ftps'),
    ...common,
    auth: z.strictObject({ type: z.literal('password'), passwordEnv: envName }),
    tls: z.enum(['explicit', 'implicit']).optional(),
    caPath: z.string().min(1).optional(),
    insecurePlainFtp: z.literal(true).optional(),
  }),
]);

const fileSchema = z.strictObject({ hosts: z.record(z.string(), hostSchema) });

function expandHome(p: string): string {
  return p === '~' || p.startsWith('~/') ? path.join(homedir(), p.slice(1)) : p;
}

export function loadConfig(file: string | undefined, env: NodeJS.ProcessEnv = process.env): Config {
  if (!file) throw new Error('SFTP_MCP_CONFIG is not set');
  if (process.platform !== 'win32' && (statSync(file).mode & 0o077) !== 0) {
    throw new Error(`Config file ${file} must not be readable by group/others (chmod 600)`);
  }
  const parsed = fileSchema.safeParse(JSON.parse(readFileSync(file, 'utf8')));
  if (!parsed.success) throw new Error(`Invalid config:\n${z.prettifyError(parsed.error)}`);

  const secrets: string[] = [];
  const hosts = new Map<string, HostConfig>();

  for (const [name, h] of Object.entries(parsed.data.hosts)) {
    if (!HOST_NAME.test(name)) throw new Error(`Invalid host name "${name}" (use a-z, 0-9, _ and -)`);
    const secret = (variable: string): string => {
      const value = env[variable];
      if (!value) throw new Error(`Host ${name}: env var ${variable} is not set`);
      secrets.push(value);
      return value;
    };

    let localRoot: string;
    try {
      localRoot = realpathSync(expandHome(h.localRoot));
    } catch {
      throw new Error(`Host ${name}: localRoot does not exist`);
    }
    if (!statSync(localRoot).isDirectory()) throw new Error(`Host ${name}: localRoot is not a directory`);

    const base = {
      name,
      host: h.host,
      username: h.username,
      remoteRoot: normalizeRemoteRoot(h.remoteRoot),
      localRoot,
      allowOverwrite: h.allowOverwrite ?? false,
      maxBytes: h.maxBytes,
      connectTimeoutMs: h.connectTimeoutMs ?? 15000,
    };

    if (h.protocol === 'sftp') {
      if (!h.hostKeySha256 === !h.knownHostsPath) {
        throw new Error(`Host ${name}: set exactly one of hostKeySha256 or knownHostsPath`);
      }
      let auth: SftpAuth;
      if (h.auth.type === 'password') {
        auth = { type: 'password', password: secret(h.auth.passwordEnv) };
      } else if (h.auth.type === 'key') {
        const passphrase = h.auth.passphraseEnv ? secret(h.auth.passphraseEnv) : undefined;
        auth = { type: 'key', privateKey: readFileSync(expandHome(h.auth.keyPath)), passphrase };
      } else {
        const agentSocket = h.auth.agentSocket ?? env.SSH_AUTH_SOCK;
        if (!agentSocket) throw new Error(`Host ${name}: agent auth needs SSH_AUTH_SOCK or agentSocket`);
        auth = { type: 'agent', agentSocket };
      }
      hosts.set(name, {
        ...base,
        protocol: 'sftp',
        port: h.port ?? 22,
        auth,
        hostKeySha256: h.hostKeySha256,
        knownHosts: h.knownHostsPath ? readFileSync(expandHome(h.knownHostsPath), 'utf8') : undefined,
      });
    } else {
      if (!h.tls && !h.insecurePlainFtp) {
        throw new Error(`Host ${name}: tls is required (set insecurePlainFtp: true to allow plain FTP)`);
      }
      if (h.tls && h.insecurePlainFtp) throw new Error(`Host ${name}: tls and insecurePlainFtp are mutually exclusive`);
      hosts.set(name, {
        ...base,
        protocol: 'ftps',
        port: h.port ?? (h.tls === 'implicit' ? 990 : 21),
        password: secret(h.auth.passwordEnv),
        tls: h.tls,
        ca: h.caPath ? readFileSync(expandHome(h.caPath), 'utf8') : undefined,
      });
    }
  }
  return { hosts, secrets };
}
