import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { loadConfig } from '../src/config.ts';

const PIN = 'SHA256:' + 'A'.repeat(43);
const env = { FTPS_PASS: 'ftps-secret', KEY_PASS: 'key-secret' };

const sftpHost = (over: object = {}) => ({
  protocol: 'sftp', host: '10.0.0.5', username: 'deploy',
  auth: { type: 'key', keyPath: '$DIR/id_test' },
  hostKeySha256: [PIN], remoteRoot: '/var/www/app/', localRoot: '$DIR/out', ...over,
});
const ftpsHost = (over: object = {}) => ({
  protocol: 'ftps', tls: 'explicit', host: 'ftp.example.com', username: 'u',
  auth: { type: 'password', passwordEnv: 'FTPS_PASS' }, remoteRoot: '/incoming', localRoot: '$DIR/out', ...over,
});

async function setup(hosts: Record<string, unknown>, mode = 0o600) {
  const dir = await realpath(await mkdtemp(path.join(tmpdir(), 'sftp-mcp-cfg-')));
  await mkdir(path.join(dir, 'out'));
  await writeFile(path.join(dir, 'id_test'), 'fake-key');
  const file = path.join(dir, 'config.json');
  await writeFile(file, JSON.stringify({ hosts }).replaceAll('$DIR', dir), { mode });
  return { file, dir };
}

test('loads sftp key host with defaults and secrets', async () => {
  const { file, dir } = await setup({ prod: sftpHost({ auth: { type: 'key', keyPath: '$DIR/id_test', passphraseEnv: 'KEY_PASS' } }) });
  const cfg = loadConfig(file, env);
  const h = cfg.hosts.get('prod');
  assert.ok(h && h.protocol === 'sftp');
  assert.equal(h.port, 22);
  assert.equal(h.remoteRoot, '/var/www/app');
  assert.equal(h.localRoot, path.join(dir, 'out'));
  assert.equal(h.allowOverwrite, false);
  assert.equal(h.connectTimeoutMs, 15000);
  assert.ok(h.auth.type === 'key');
  assert.equal(h.auth.privateKey.toString(), 'fake-key');
  assert.equal(h.auth.passphrase, 'key-secret');
  assert.deepEqual(cfg.secrets, ['key-secret']);
});

test('loads ftps hosts with protocol default ports', async () => {
  const { file } = await setup({ ex: ftpsHost(), im: ftpsHost({ tls: 'implicit' }) });
  const cfg = loadConfig(file, env);
  const ex = cfg.hosts.get('ex');
  assert.ok(ex && ex.protocol === 'ftps');
  assert.equal(ex.port, 21);
  assert.equal(ex.password, 'ftps-secret');
  assert.equal(cfg.hosts.get('im')?.port, 990);
});

test('rejects missing env var', async () => {
  const { file } = await setup({ ex: ftpsHost() });
  assert.throws(() => loadConfig(file, {}), /FTPS_PASS is not set/);
});

test('rejects literal password in config', async () => {
  const { file } = await setup({ ex: ftpsHost({ auth: { type: 'password', passwordEnv: 'FTPS_PASS', password: 'oops' } }) });
  assert.throws(() => loadConfig(file, env), /Invalid config/);
});

test('rejects bad fingerprint format', async () => {
  const { file } = await setup({ prod: sftpHost({ hostKeySha256: ['SHA256:short'] }) });
  assert.throws(() => loadConfig(file, env), /Invalid config/);
});

test('sftp requires exactly one host key source', async () => {
  const none = await setup({ prod: sftpHost({ hostKeySha256: undefined }) });
  assert.throws(() => loadConfig(none.file, env), /exactly one of hostKeySha256 or knownHostsPath/);
  const both = await setup({ prod: sftpHost({ knownHostsPath: '$DIR/id_test' }) });
  assert.throws(() => loadConfig(both.file, env), /exactly one of hostKeySha256 or knownHostsPath/);
});

test('ftps requires tls unless insecurePlainFtp', async () => {
  const noTls = await setup({ ex: ftpsHost({ tls: undefined }) });
  assert.throws(() => loadConfig(noTls.file, env), /tls is required/);
  const plain = await setup({ ex: ftpsHost({ tls: undefined, insecurePlainFtp: true }) });
  const h = loadConfig(plain.file, env).hosts.get('ex');
  assert.ok(h && h.protocol === 'ftps' && h.tls === undefined && h.port === 21);
});

test('rejects invalid host name', async () => {
  const { file } = await setup({ 'Prod Web': sftpHost() });
  assert.throws(() => loadConfig(file, env), /Invalid host name/);
});

test('rejects group/world readable config', { skip: process.platform === 'win32' }, async () => {
  const { file } = await setup({ prod: sftpHost() }, 0o644);
  assert.throws(() => loadConfig(file, env), /chmod 600/);
});

test('rejects missing localRoot', async () => {
  const { file } = await setup({ prod: sftpHost({ localRoot: '$DIR/nope' }) });
  assert.throws(() => loadConfig(file, env), /localRoot does not exist/);
});

test('agent auth needs a socket', async () => {
  const { file } = await setup({ prod: sftpHost({ auth: { type: 'agent' } }) });
  assert.throws(() => loadConfig(file, env), /SSH_AUTH_SOCK/);
  const h = loadConfig(file, { ...env, SSH_AUTH_SOCK: '/tmp/agent.sock' }).hosts.get('prod');
  assert.ok(h && h.protocol === 'sftp' && h.auth.type === 'agent' && h.auth.agentSocket === '/tmp/agent.sock');
});

test('rejects unset SFTP_MCP_CONFIG', () => {
  assert.throws(() => loadConfig(undefined, env), /SFTP_MCP_CONFIG is not set/);
});
