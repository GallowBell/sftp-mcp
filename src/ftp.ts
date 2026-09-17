import { isIP } from 'node:net';
import path from 'node:path';
import { rootCertificates } from 'node:tls';
import ftp, { type Client, type FileInfo, type FileType } from 'basic-ftp';
import { partPath } from './paths.js';
import { MAX_ENTRIES, type Entry, type EntryType, type FtpsHost, type StatResult, type UploadResult } from './types.js';

function entryType(t: FileType): EntryType {
  if (t === ftp.FileType.File) return 'file';
  if (t === ftp.FileType.Directory) return 'dir';
  if (t === ftp.FileType.SymbolicLink) return 'link';
  return 'other';
}

function toEntry(i: FileInfo): Entry {
  return { name: i.name, type: entryType(i.type), size: i.size, modifiedAt: i.modifiedAt?.toISOString() ?? null };
}

async function withClient<T>(h: FtpsHost, fn: (c: Client) => Promise<T>): Promise<T> {
  const client = new ftp.Client(h.connectTimeoutMs);
  try {
    await client.access({
      host: h.host,
      port: h.port,
      user: h.username,
      password: h.password,
      secure: h.tls === 'implicit' ? 'implicit' : h.tls === 'explicit',
      secureOptions: h.tls
        ? {
            host: h.host,
            servername: isIP(h.host) ? undefined : h.host,
            rejectUnauthorized: true,
            minVersion: 'TLSv1.2',
            ca: h.ca ? [...rootCertificates, h.ca] : undefined,
          }
        : undefined,
    });
    return await fn(client);
  } finally {
    client.close();
  }
}

async function statWith(c: Client, remotePath: string): Promise<StatResult> {
  if (remotePath === '/') return { exists: true, type: 'dir', size: 0, modifiedAt: null };
  let items: FileInfo[];
  try {
    items = await c.list(path.posix.dirname(remotePath));
  } catch (err) {
    if (err instanceof ftp.FTPError && err.code === 550) return { exists: false };
    throw err;
  }
  const found = items.find((i) => i.name === path.posix.basename(remotePath));
  if (found) {
    const { type, size, modifiedAt } = toEntry(found);
    return { exists: true, type, size, modifiedAt };
  }
  try {
    const size = await c.size(remotePath);
    return { exists: true, type: 'file', size, modifiedAt: null };
  } catch (err) {
    if (err instanceof ftp.FTPError && err.code === 550) return { exists: false };
    throw err;
  }
}

export function stat(h: FtpsHost, remotePath: string): Promise<StatResult> {
  return withClient(h, (c) => statWith(c, remotePath));
}

export function listDir(h: FtpsHost, remotePath: string): Promise<{ entries: Entry[]; truncated: boolean }> {
  return withClient(h, async (c) => {
    const items = (await c.list(remotePath)).filter((i) => i.name !== '.' && i.name !== '..');
    return { entries: items.slice(0, MAX_ENTRIES).map(toEntry), truncated: items.length > MAX_ENTRIES };
  });
}

export function upload(h: FtpsHost, localPath: string, remotePath: string, bytes: number): Promise<UploadResult> {
  return withClient(h, async (c) => {
    const existing = await statWith(c, remotePath);
    if (existing.exists && existing.type === 'dir') throw new Error('Remote path is a directory');
    if (existing.exists && !h.allowOverwrite) throw new Error('Remote file exists and overwrite is disabled');
    const tmp = partPath(remotePath);
    try {
      await c.uploadFrom(localPath, tmp);
      await c.rename(tmp, remotePath);
    } catch (err) {
      await c.remove(tmp, true).catch(() => {});
      throw err;
    }
    return { remotePath, bytes, overwritten: existing.exists };
  });
}
