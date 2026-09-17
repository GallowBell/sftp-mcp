import { after, before, describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { chmod, copyFile, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import * as sftp from '../src/sftp.ts';
import type { SftpHost } from '../src/types.ts';

const FIX = path.resolve(import.meta.dirname, 'fixtures');

describe('sftp integration', { skip: process.env.INTEGRATION !== '1' }, () => {
  let localRoot: string;
  let file: string;
  let pin: string;
  let agentPid: number | undefined;
  let agentSock = '';

  before(async () => {
    localRoot = await mkdtemp(path.join(tmpdir(), 'sftp-mcp-it-'));
    file = path.join(localRoot, 'hello.txt');
    await writeFile(file, 'hello sftp'); // 10 bytes
    pin = (await readFile(path.join(FIX, 'host_fingerprint.txt'), 'utf8')).trim();

    const keyCopy = path.join(localRoot, 'agent_key');
    await copyFile(path.join(FIX, 'user_ed25519'), keyCopy);
    await chmod(keyCopy, 0o600);
    const out = execFileSync('ssh-agent', ['-s'], { encoding: 'utf8' });
    agentSock = /SSH_AUTH_SOCK=([^;]+);/.exec(out)![1];
    agentPid = Number(/SSH_AGENT_PID=(\d+);/.exec(out)![1]);
    execFileSync('ssh-add', [keyCopy], { env: { ...process.env, SSH_AUTH_SOCK: agentSock }, stdio: 'ignore' });
  });

  after(() => {
    if (agentPid) process.kill(agentPid);
  });

  const host = (over: Partial<SftpHost> = {}): SftpHost => ({
    name: 'it', protocol: 'sftp', host: '127.0.0.1', port: 2222, username: 'tester',
    auth: { type: 'password', password: 'testpass' }, hostKeySha256: [pin],
    remoteRoot: '/upload', localRoot, allowOverwrite: false, connectTimeoutMs: 10000, ...over,
  });
  const unique = (n: string) => `/upload/${Date.now()}-${Math.random().toString(16).slice(2)}-${n}`;

  test('password auth uploads; stat and listDir see it; no .part left', async () => {
    const remote = unique('a.txt');
    assert.deepEqual(await sftp.upload(host(), file, remote, 10), { remotePath: remote, bytes: 10, overwritten: false });
    const s = await sftp.stat(host(), remote);
    assert.ok(s.exists && s.type === 'file' && s.size === 10);
    const { entries, truncated } = await sftp.listDir(host(), '/upload');
    assert.equal(truncated, false);
    assert.ok(entries.some((e) => e.name === path.posix.basename(remote)));
    assert.ok(!entries.some((e) => e.name.endsWith('.part')));
  });

  test('private key auth uploads', async () => {
    const privateKey = await readFile(path.join(FIX, 'user_ed25519'));
    const r = await sftp.upload(host({ auth: { type: 'key', privateKey } }), file, unique('k.txt'), 10);
    assert.equal(r.overwritten, false);
  });

  test('ssh-agent auth uploads', async () => {
    const r = await sftp.upload(host({ auth: { type: 'agent', agentSocket: agentSock } }), file, unique('g.txt'), 10);
    assert.equal(r.overwritten, false);
  });

  test('known_hosts content verifies host', async () => {
    const pub = (await readFile(path.join(FIX, 'ssh_host_ed25519_key.pub'), 'utf8')).trim();
    const knownHosts = `[127.0.0.1]:2222 ${pub}\n`;
    const s = await sftp.stat(host({ hostKeySha256: undefined, knownHosts }), '/upload');
    assert.ok(s.exists && s.type === 'dir');
  });

  test('wrong host key pin is rejected and nothing is uploaded', async () => {
    const remote = unique('bad.txt');
    await assert.rejects(
      sftp.upload(host({ hostKeySha256: ['SHA256:' + 'A'.repeat(43)] }), file, remote, 10),
      /Host key verification failed for it/,
    );
    assert.deepEqual(await sftp.stat(host(), remote), { exists: false });
  });

  test('overwrite is refused unless allowed', async () => {
    const remote = unique('o.txt');
    await sftp.upload(host(), file, remote, 10);
    await assert.rejects(sftp.upload(host(), file, remote, 10), /overwrite is disabled/);
    const changed = path.join(localRoot, 'changed.txt');
    await writeFile(changed, 'changed content!'); // 16 bytes
    const r = await sftp.upload(host({ allowOverwrite: true }), changed, remote, 16);
    assert.equal(r.overwritten, true);
    const s = await sftp.stat(host(), remote);
    assert.ok(s.exists && s.size === 16);
  });

  test('stat of missing path', async () => {
    assert.deepEqual(await sftp.stat(host(), unique('missing.txt')), { exists: false });
  });
});
