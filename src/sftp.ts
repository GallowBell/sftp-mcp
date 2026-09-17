import type { Algorithms } from 'ssh2';
import SftpClient from 'ssh2-sftp-client';
import { matchesFingerprint, matchesKnownHosts } from './hostkey.js';
import { partPath } from './paths.js';
import { MAX_ENTRIES, type Entry, type EntryType, type SftpHost, type StatResult, type UploadResult } from './types.js';

export const SSH_ALGORITHMS: Algorithms = {
  kex: [
    'curve25519-sha256', 'curve25519-sha256@libssh.org',
    'ecdh-sha2-nistp256', 'ecdh-sha2-nistp384', 'ecdh-sha2-nistp521',
    'diffie-hellman-group16-sha512', 'diffie-hellman-group18-sha512', 'diffie-hellman-group14-sha256',
  ],
  cipher: [
    'chacha20-poly1305@openssh.com', 'aes256-gcm@openssh.com', 'aes128-gcm@openssh.com',
    'aes256-ctr', 'aes192-ctr', 'aes128-ctr',
  ],
  hmac: ['hmac-sha2-256-etm@openssh.com', 'hmac-sha2-512-etm@openssh.com', 'hmac-sha2-256', 'hmac-sha2-512'],
  serverHostKey: [
    'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521',
    'rsa-sha2-512', 'rsa-sha2-256',
  ],
};

const LIST_TYPE: Record<string, EntryType> = { '-': 'file', d: 'dir', l: 'link' };

async function withClient<T>(h: SftpHost, fn: (c: SftpClient) => Promise<T>): Promise<T> {
  const client = new SftpClient('sftp-mcp', {
    error: (err: unknown) => console.error(`sftp-mcp: ${err instanceof Error ? err.message : String(err)}`),
    end: () => {},
    close: () => {},
  });
  let hostKeyRejected = false;
  const auth =
    h.auth.type === 'password' ? { password: h.auth.password }
    : h.auth.type === 'key' ? { privateKey: h.auth.privateKey, passphrase: h.auth.passphrase }
    : { agent: h.auth.agentSocket };
  try {
    await client.connect({
      host: h.host,
      port: h.port,
      username: h.username,
      ...auth,
      readyTimeout: h.connectTimeoutMs,
      keepaliveInterval: 10000,
      keepaliveCountMax: 3,
      algorithms: SSH_ALGORITHMS,
      hostVerifier: (key: Buffer) => {
        const ok = h.hostKeySha256
          ? matchesFingerprint(key, h.hostKeySha256)
          : matchesKnownHosts(key, h.knownHosts ?? '', h.host, h.port);
        if (!ok) hostKeyRejected = true;
        return ok;
      },
    });
  } catch (err) {
    await client.end().catch(() => {});
    (client as unknown as { client: { end: () => void } }).client.end();
    if (hostKeyRejected) throw new Error(`Host key verification failed for ${h.name}`);
    throw err;
  }
  try {
    return await fn(client);
  } finally {
    await client.end().catch(() => {});
  }
}

async function statWith(c: SftpClient, remotePath: string): Promise<StatResult> {
  const kind = await c.exists(remotePath);
  if (!kind) return { exists: false };
  if (kind === 'l') return { exists: true, type: 'link', size: 0, modifiedAt: null };
  const s = await c.stat(remotePath);
  return { exists: true, type: LIST_TYPE[kind] ?? 'other', size: s.size, modifiedAt: new Date(s.modifyTime).toISOString() };
}

export function stat(h: SftpHost, remotePath: string): Promise<StatResult> {
  return withClient(h, (c) => statWith(c, remotePath));
}

export function listDir(h: SftpHost, remotePath: string): Promise<{ entries: Entry[]; truncated: boolean }> {
  return withClient(h, async (c) => {
    const items = await c.list(remotePath);
    const entries = items.slice(0, MAX_ENTRIES).map((i) => ({
      name: i.name,
      type: LIST_TYPE[i.type] ?? 'other',
      size: i.size,
      modifiedAt: new Date(i.modifyTime).toISOString(),
    }));
    return { entries, truncated: items.length > MAX_ENTRIES };
  });
}

export function upload(h: SftpHost, localPath: string, remotePath: string, bytes: number): Promise<UploadResult> {
  return withClient(h, async (c) => {
    const existing = await statWith(c, remotePath);
    if (existing.exists && existing.type === 'dir') throw new Error('Remote path is a directory');
    if (existing.exists && !h.allowOverwrite) throw new Error('Remote file exists and overwrite is disabled');
    const tmp = partPath(remotePath);
    try {
      await c.put(localPath, tmp);
      if (existing.exists) await c.posixRename(tmp, remotePath);
      else await c.rename(tmp, remotePath);
    } catch (err) {
      await c.delete(tmp, true).catch(() => {});
      throw err;
    }
    return { remotePath, bytes, overwritten: existing.exists };
  });
}
