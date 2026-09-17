import { before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as ftps from '../src/ftp.ts';
import type { FtpsHost } from '../src/types.ts';

const FIX = path.resolve(import.meta.dirname, 'fixtures');

describe('ftps integration', { skip: process.env.INTEGRATION !== '1' }, () => {
  let localRoot: string;
  let file: string;
  let ca: string;

  before(async () => {
    localRoot = await mkdtemp(path.join(tmpdir(), 'sftp-mcp-ftps-'));
    file = path.join(localRoot, 'hello.txt');
    await writeFile(file, 'hello ftps'); // 10 bytes
    ca = await readFile(path.join(FIX, 'ca.crt'), 'utf8');
  });

  const host = (over: Partial<FtpsHost> = {}): FtpsHost => ({
    name: 'it', protocol: 'ftps', host: 'localhost', port: 2121, tls: 'explicit', ca,
    username: 'ftpuser', password: 'ftppass', remoteRoot: '/upload', localRoot,
    allowOverwrite: false, connectTimeoutMs: 10000, ...over,
  });
  const unique = (n: string) => `/upload/${Date.now()}-${Math.random().toString(16).slice(2)}-${n}`;

  test('explicit TLS uploads; stat and listDir see it; no .part left', async () => {
    const remote = unique('a.txt');
    assert.deepEqual(await ftps.upload(host(), file, remote, 10), { remotePath: remote, bytes: 10, overwritten: false });
    const s = await ftps.stat(host(), remote);
    assert.ok(s.exists && s.type === 'file' && s.size === 10);
    const { entries } = await ftps.listDir(host(), '/upload');
    assert.ok(entries.some((e) => e.name === path.posix.basename(remote)));
    assert.ok(!entries.some((e) => e.name.endsWith('.part')));
  });

  test('implicit TLS uploads', async () => {
    const r = await ftps.upload(host({ tls: 'implicit', port: 2990 }), file, unique('i.txt'), 10);
    assert.equal(r.overwritten, false);
  });

  test('untrusted certificate is rejected', async () => {
    await assert.rejects(ftps.stat(host({ ca: undefined }), '/upload'), /self.signed|unable to (get|verify)|certificate/i);
  });

  test('hostname mismatch is rejected', async () => {
    await assert.rejects(ftps.stat(host({ host: '127.0.0.1' }), '/upload'), /IP|altname|does not match|certificate/i);
  });

  test('overwrite is refused unless allowed', async () => {
    const remote = unique('o.txt');
    await ftps.upload(host(), file, remote, 10);
    await assert.rejects(ftps.upload(host(), file, remote, 10), /overwrite is disabled/);
    const changed = path.join(localRoot, 'changed.txt');
    await writeFile(changed, 'changed content!'); // 16 bytes
    assert.equal((await ftps.upload(host({ allowOverwrite: true }), changed, remote, 16)).overwritten, true);
    const s = await ftps.stat(host(), remote);
    assert.ok(s.exists && s.size === 16);
  });

  test('dotfile overwrite is refused even when hidden from LIST', async () => {
    const remote = `/upload/.hidden-${Date.now()}-${Math.random().toString(16).slice(2)}.txt`;
    await ftps.upload(host(), file, remote, 10);
    await assert.rejects(ftps.upload(host(), file, remote, 10), /overwrite is disabled/);
  });

  test('stat of missing path and missing parent', async () => {
    assert.deepEqual(await ftps.stat(host(), unique('missing.txt')), { exists: false });
    assert.deepEqual(await ftps.stat(host(), '/upload/no-such-dir/x.txt'), { exists: false });
  });
});
