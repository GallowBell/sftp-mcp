import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, symlink, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { normalizeRemoteRoot, partPath, resolveLocalFile, resolveRemote, resolveRemoteFile } from '../src/paths.ts';

const ROOT = '/var/www/app';

test('normalizeRemoteRoot strips trailing slash and requires absolute', () => {
  assert.equal(normalizeRemoteRoot('/var/www/app/'), '/var/www/app');
  assert.equal(normalizeRemoteRoot('/'), '/');
  assert.throws(() => normalizeRemoteRoot('var/www'), /absolute/);
});

test('resolveRemote joins relative and accepts absolute inside root', () => {
  assert.equal(resolveRemote(ROOT, 'index.html'), '/var/www/app/index.html');
  assert.equal(resolveRemote(ROOT, '/var/www/app/a/b.txt'), '/var/www/app/a/b.txt');
  assert.equal(resolveRemote(ROOT, ''), ROOT);
  assert.equal(resolveRemote(ROOT, 'assets/'), '/var/www/app/assets');
  assert.equal(resolveRemote('/', 'upload/a.txt'), '/upload/a.txt');
});

test('resolveRemote rejects traversal, outside paths, and odd characters', () => {
  assert.throws(() => resolveRemote(ROOT, '../x'), /\.\./);
  assert.throws(() => resolveRemote(ROOT, 'a/../../x'), /\.\./);
  assert.throws(() => resolveRemote(ROOT, '/var/www/app/../secret'), /\.\./);
  assert.throws(() => resolveRemote(ROOT, '/etc/passwd'), /outside remoteRoot/);
  assert.throws(() => resolveRemote(ROOT, '/var/www/app2/x'), /outside remoteRoot/);
  assert.throws(() => resolveRemote(ROOT, 'a\\b'), /Invalid remote path/);
  assert.throws(() => resolveRemote(ROOT, 'a\0b'), /Invalid remote path/);
});

test('resolveRemoteFile rejects root and directory-looking paths', () => {
  assert.equal(resolveRemoteFile(ROOT, 'a.txt'), '/var/www/app/a.txt');
  assert.throws(() => resolveRemoteFile(ROOT, 'dir/'), /must name a file/);
  assert.throws(() => resolveRemoteFile(ROOT, ROOT), /must name a file/);
  assert.throws(() => resolveRemoteFile(ROOT, '.'), /must name a file/);
});

test('partPath is a hidden sibling with random suffix', () => {
  assert.match(partPath('/r/a/file.txt'), /^\/r\/a\/\.file\.txt\.[0-9a-f]{8}\.part$/);
});

test('resolveLocalFile confines to localRoot', async () => {
  const base = await realpath(await mkdtemp(path.join(tmpdir(), 'sftp-mcp-paths-')));
  const root = path.join(base, 'root');
  await mkdir(path.join(root, 'sub'), { recursive: true });
  await writeFile(path.join(root, 'a.txt'), 'hello');
  await writeFile(path.join(base, 'outside.txt'), 'nope');
  await symlink(path.join(base, 'outside.txt'), path.join(root, 'link.txt'));

  assert.deepEqual(await resolveLocalFile(root, 'a.txt'), { path: path.join(root, 'a.txt'), size: 5 });
  assert.deepEqual(await resolveLocalFile(root, path.join(root, 'a.txt')), { path: path.join(root, 'a.txt'), size: 5 });
  await assert.rejects(resolveLocalFile(root, '../outside.txt'), /outside localRoot/);
  await assert.rejects(resolveLocalFile(root, 'link.txt'), /outside localRoot/);
  await assert.rejects(resolveLocalFile(root, 'sub'), /not a regular file/);
  await assert.rejects(resolveLocalFile(root, 'missing.txt'), /not found/);
  await assert.rejects(resolveLocalFile(root, 'a\0.txt'), /Invalid local path/);
});
