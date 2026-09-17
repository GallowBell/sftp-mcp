import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, realpath, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createServer, redact } from '../src/server.ts';
import type { HostConfig } from '../src/types.ts';

async function fixture() {
  const localRoot = await realpath(await mkdtemp(path.join(tmpdir(), 'sftp-mcp-srv-')));
  await writeFile(path.join(localRoot, 'big.bin'), Buffer.alloc(2048));
  const outside = await mkdtemp(path.join(tmpdir(), 'sftp-mcp-outside-'));
  await writeFile(path.join(outside, 'secret.txt'), 'x');
  const base = { host: '127.0.0.1', port: 1, username: 'u', remoteRoot: '/upload', localRoot, allowOverwrite: false, connectTimeoutMs: 2000 };
  const hosts = new Map<string, HostConfig>([
    ['web', { ...base, name: 'web', protocol: 'sftp', auth: { type: 'password', password: 'hunter2-secret' }, hostKeySha256: ['SHA256:' + 'A'.repeat(43)], maxBytes: 1024 }],
    ['plain', { ...base, name: 'plain', protocol: 'ftps', password: 'ftp-secret' }],
  ]);
  const server = createServer({ hosts, secrets: ['hunter2-secret', 'ftp-secret'] });
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(clientSide);
  return { client, outside };
}

async function call(client: Client, name: string, args: Record<string, unknown> = {}) {
  const res = await client.callTool({ name, arguments: args });
  return { isError: res.isError === true, text: (res.content as Array<{ text: string }>)[0].text };
}

test('redact replaces every secret occurrence', () => {
  assert.equal(redact('a hunter2 b hunter2', ['hunter2']), 'a *** b ***');
});

test('exposes exactly the four tools', async () => {
  const { client } = await fixture();
  const names = (await client.listTools()).tools.map((t) => t.name).sort();
  assert.deepEqual(names, ['list_dir', 'list_hosts', 'stat', 'upload_file']);
});

test('list_hosts shows hosts without secrets and flags plain FTP', async () => {
  const { client } = await fixture();
  const { isError, text } = await call(client, 'list_hosts');
  assert.equal(isError, false);
  assert.ok(!text.includes('hunter2-secret') && !text.includes('ftp-secret'));
  const hosts = JSON.parse(text);
  assert.deepEqual(hosts.map((h: { name: string; insecure: boolean }) => [h.name, h.insecure]), [['web', false], ['plain', true]]);
});

test('unknown host is an error', async () => {
  const { client } = await fixture();
  assert.deepEqual(await call(client, 'stat', { host: 'nope', remotePath: 'x' }), { isError: true, text: 'Unknown host' });
});

test('remote traversal is rejected before connecting', async () => {
  const { client } = await fixture();
  const r = await call(client, 'upload_file', { host: 'web', localPath: 'big.bin', remotePath: '../etc/passwd' });
  assert.equal(r.isError, true);
  assert.match(r.text, /\.\./);
});

test('local path outside localRoot is rejected', async () => {
  const { client, outside } = await fixture();
  const r = await call(client, 'upload_file', { host: 'web', localPath: path.join(outside, 'secret.txt'), remotePath: 'a.txt' });
  assert.equal(r.isError, true);
  assert.match(r.text, /outside localRoot/);
});

test('maxBytes is enforced before connecting', async () => {
  const { client } = await fixture();
  const r = await call(client, 'upload_file', { host: 'web', localPath: 'big.bin', remotePath: 'big.bin' });
  assert.equal(r.isError, true);
  assert.match(r.text, /exceeds maxBytes/);
});

test('connection failure returns an error without secrets', async () => {
  const { client } = await fixture();
  const r = await call(client, 'stat', { host: 'web', remotePath: 'x' });
  assert.equal(r.isError, true);
  assert.ok(!r.text.includes('hunter2-secret'));
});

test('error text that echoes a secret is redacted', async () => {
  const dnsSecret = 'hunter2-secret.invalid';
  const localRoot = await realpath(await mkdtemp(path.join(tmpdir(), 'sftp-mcp-srv-')));
  const hosts = new Map<string, HostConfig>([
    ['dns', {
      host: dnsSecret, port: 1, username: 'u', remoteRoot: '/upload', localRoot,
      allowOverwrite: false, connectTimeoutMs: 5000,
      name: 'dns', protocol: 'sftp', auth: { type: 'password', password: 'irrelevant' },
      hostKeySha256: ['SHA256:' + 'A'.repeat(43)],
    }],
  ]);
  const server = createServer({ hosts, secrets: [dnsSecret] });
  const [serverSide, clientSide] = InMemoryTransport.createLinkedPair();
  await server.connect(serverSide);
  const client = new Client({ name: 'test', version: '0.0.0' });
  await client.connect(clientSide);

  const r = await call(client, 'stat', { host: 'dns', remotePath: 'x' });
  assert.equal(r.isError, true);
  assert.ok(r.text.includes('***'));
  assert.ok(!r.text.includes(dnsSecret));
});
