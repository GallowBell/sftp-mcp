import { randomBytes } from 'node:crypto';
import { realpath, stat } from 'node:fs/promises';
import path from 'node:path';

function isInside(root: string, p: string, sep: string): boolean {
  return p === root || p.startsWith(root.endsWith(sep) ? root : root + sep);
}

export function normalizeRemoteRoot(root: string): string {
  if (!root.startsWith('/')) throw new Error('remoteRoot must be an absolute POSIX path');
  const n = path.posix.normalize(root);
  return n.length > 1 && n.endsWith('/') ? n.slice(0, -1) : n;
}

export function resolveRemote(root: string, input: string): string {
  if (input.includes('\0') || input.includes('\\')) throw new Error('Invalid remote path');
  if (input.split('/').includes('..')) throw new Error('Remote path must not contain ".."');
  let full = path.posix.normalize(input.startsWith('/') ? input : path.posix.join(root, input));
  if (full.length > 1 && full.endsWith('/')) full = full.slice(0, -1);
  if (!isInside(root, full, '/')) throw new Error('Remote path is outside remoteRoot');
  return full;
}

export function resolveRemoteFile(root: string, input: string): string {
  if (input.endsWith('/')) throw new Error('Remote path must name a file');
  const full = resolveRemote(root, input);
  if (full === root) throw new Error('Remote path must name a file');
  return full;
}

export async function resolveLocalFile(root: string, input: string): Promise<{ path: string; size: number }> {
  if (input.includes('\0')) throw new Error('Invalid local path');
  let real: string;
  try {
    real = await realpath(path.resolve(root, input));
  } catch {
    throw new Error('Local file not found');
  }
  if (!isInside(root, real, path.sep)) throw new Error('Local path is outside localRoot');
  const s = await stat(real);
  if (!s.isFile()) throw new Error('Local path is not a regular file');
  return { path: real, size: s.size };
}

export function partPath(remotePath: string): string {
  const name = `.${path.posix.basename(remotePath)}.${randomBytes(4).toString('hex')}.part`;
  return path.posix.join(path.posix.dirname(remotePath), name);
}
